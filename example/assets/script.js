// The client side of the beeper example. It reloads every asset the page
// references, times each one, and reports what came back, which is the
// difference the fast path is meant to make visible: the small assets are
// answered from the kernel, the images are not.
//
// Nothing here is required for the page to render. It only measures.

(function () {
    "use strict";

    // Every asset the page is made of, in the order the table lists them.
    // `fastpath` says whether the server was asked to answer this one from
    // eBPF, which is a property of how it was started, not of the file.
    const ASSETS = [
        { path: "/index.html", kind: "document", fastpath: true },
        { path: "/style.css", kind: "stylesheet", fastpath: true },
        { path: "/script.js", kind: "script", fastpath: true },
        { path: "/honeycomb.png", kind: "image", fastpath: false },
        { path: "/rings.png", kind: "image", fastpath: false },
        { path: "/stripes.png", kind: "image", fastpath: false },
    ];

    // How many times each asset is fetched before its timings are summarised.
    // A single request is dominated by whatever the connection was doing at
    // the time, so a handful are taken and the median reported.
    const RUNS = 5;

    /** Formats a byte count the way a human reads one. */
    function formatBytes(n) {
        if (n < 1024) {
            return n + " B";
        }
        if (n < 1024 * 1024) {
            return (n / 1024).toFixed(1) + " KiB";
        }
        return (n / (1024 * 1024)).toFixed(2) + " MiB";
    }

    /** Formats a duration in milliseconds. */
    function formatMs(ms) {
        if (ms < 1) {
            return ms.toFixed(2) + " ms";
        }
        if (ms < 100) {
            return ms.toFixed(1) + " ms";
        }
        return Math.round(ms) + " ms";
    }

    /** Returns the median of `values`, which is left unsorted. */
    function median(values) {
        if (values.length === 0) {
            return NaN;
        }

        const sorted = values.slice().sort(function (a, b) {
            return a - b;
        });
        const mid = Math.floor(sorted.length / 2);

        return sorted.length % 2 === 0
            ? (sorted[mid - 1] + sorted[mid]) / 2
            : sorted[mid];
    }

    /** Returns the smallest of `values`. */
    function min(values) {
        return values.reduce(function (a, b) {
            return a < b ? a : b;
        }, Infinity);
    }

    /**
     * Fetches `path` once and returns how long it took and how much came back.
     *
     * The cache is bypassed with a query string rather than a `Cache-Control`
     * header: a header would turn the request into one the fast path does not
     * recognise, and the point is to measure the request the browser would
     * really make. The query string is dropped by the server's router, but it
     * is enough to keep the browser from answering out of its own cache.
     */
    async function timeOnce(path, nonce) {
        const url = path + "?_=" + nonce;
        const started = performance.now();

        const response = await fetch(url, { cache: "no-store" });
        const body = await response.arrayBuffer();

        const elapsed = performance.now() - started;

        return {
            ok: response.ok,
            status: response.status,
            bytes: body.byteLength,
            ms: elapsed,
        };
    }

    /** Fetches `asset` `RUNS` times and summarises the results. */
    async function measure(asset, onProgress) {
        const samples = [];
        let bytes = 0;
        let status = 0;
        let ok = true;

        for (let i = 0; i < RUNS; i++) {
            let result;
            try {
                result = await timeOnce(asset.path, Date.now() + "-" + i);
            } catch (err) {
                return {
                    asset: asset,
                    error: String(err),
                    ok: false,
                };
            }

            samples.push(result.ms);
            bytes = result.bytes;
            status = result.status;
            ok = ok && result.ok;

            if (onProgress) {
                onProgress(i + 1, RUNS);
            }
        }

        return {
            asset: asset,
            ok: ok,
            status: status,
            bytes: bytes,
            median: median(samples),
            best: min(samples),
            samples: samples,
        };
    }

    /** Builds one row of the results table. */
    function renderRow(result) {
        const row = document.createElement("tr");
        const asset = result.asset;

        function cell(text, className) {
            const td = document.createElement("td");
            td.textContent = text;
            if (className) {
                td.className = className;
            }
            row.appendChild(td);
            return td;
        }

        cell(asset.path, "path");
        cell(asset.kind, "kind");

        if (!result.ok) {
            const td = cell(result.error || "HTTP " + result.status, "bad");
            td.colSpan = 4;
            return row;
        }

        cell(formatBytes(result.bytes), "num");
        cell(formatMs(result.median), "num");
        cell(formatMs(result.best), "num");
        cell(asset.fastpath ? "kernel" : "user space", asset.fastpath ? "fast" : "slow");

        return row;
    }

    /** Renders the summary line above the table. */
    function renderSummary(results) {
        const served = results.filter(function (r) {
            return r.ok;
        });
        const failed = results.length - served.length;

        const total = served.reduce(function (acc, r) {
            return acc + r.bytes;
        }, 0);

        const parts = [
            served.length + " of " + results.length + " assets",
            formatBytes(total) + " in total",
            RUNS + " requests each",
        ];

        if (failed > 0) {
            parts.push(failed + " failed");
        }

        return parts.join(" · ");
    }

    /** Runs every measurement and fills the table in as it goes. */
    async function run() {
        const table = document.getElementById("results");
        const tbody = table.querySelector("tbody");
        const summary = document.getElementById("summary");
        const button = document.getElementById("rerun");

        button.disabled = true;
        tbody.textContent = "";
        summary.textContent = "measuring…";

        const results = [];
        for (const asset of ASSETS) {
            summary.textContent = "measuring " + asset.path + "…";

            const result = await measure(asset);
            results.push(result);
            tbody.appendChild(renderRow(result));
        }

        summary.textContent = renderSummary(results);
        button.disabled = false;

        return results;
    }

    /**
     * Reports which protocol the page itself was served over, which is worth
     * knowing here: the fast path answers HTTP/1.1 and HTTP/2 by different
     * routes, and the dynamic table handover only exists for the latter.
     */
    function reportProtocol() {
        const el = document.getElementById("protocol");
        const entries = performance.getEntriesByType("navigation");

        if (entries.length > 0 && entries[0].nextHopProtocol) {
            el.textContent = entries[0].nextHopProtocol;
        } else {
            el.textContent = "unknown";
        }
    }

    function init() {
        reportProtocol();

        document.getElementById("rerun").addEventListener("click", function () {
            run();
        });

        run();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
