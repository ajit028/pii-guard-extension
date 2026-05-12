console.log("PII Guard Loaded");

/**
 * Detection patterns
 */
const patterns = [

    {
        type: "Email",
        severity: "LOW",
        regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi
    },

    {
        type: "Phone",
        severity: "MEDIUM",
        regex: /\b\d{10}\b/g
    },

    {
        type: "Aadhaar",
        severity: "HIGH",
        regex: /\b\d{4}\s?\d{4}\s?\d{4}\b/g
    },

    {
        type: "PAN",
        severity: "MEDIUM",
        regex: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g
    },

    {
        type: "Credit Card",
        severity: "HIGH",
        regex: /\b(?:\d[ -]*?){13,16}\b/g
    },

    {
        type: "OpenAI API Key",
        severity: "CRITICAL",
        regex: /\bsk-[A-Za-z0-9]{20,}\b/g
    }

];

/**
 * Current editor
 */
let activeEditor = null;

/**
 * Scan PII
 */
function scanPII(text) {

    const detections = [];

    patterns.forEach((pattern) => {

        const regex = new RegExp(pattern.regex);

        let match;

        while ((match = regex.exec(text)) !== null) {

            detections.push({

                type: pattern.type,

                severity: pattern.severity,

                value: match[0]

            });

        }

    });

    return detections;
}

/**
 * Create panel
 */
function createRiskPanel() {

    let panel =
        document.getElementById("pii-risk-panel");

    if (panel) return panel;

    panel = document.createElement("div");

    panel.id = "pii-risk-panel";

    panel.innerHTML = `
        <div class="pii-title">
            ⚠ Sensitive Data Detected
        </div>

        <div id="pii-content"></div>
    `;

    document.body.appendChild(panel);

    return panel;
}

/**
 * Highlight text visually
 */
function highlightInEditor(value) {

    if (!activeEditor) return;

    const selection =
        window.getSelection();

    const walker =
        document.createTreeWalker(
            activeEditor,
            NodeFilter.SHOW_TEXT
        );

    let node;

    while ((node = walker.nextNode())) {

        const index =
            node.nodeValue.indexOf(value);

        if (index !== -1) {

            const range =
                document.createRange();

            range.setStart(node, index);

            range.setEnd(
                node,
                index + value.length
            );

            selection.removeAllRanges();

            selection.addRange(range);

            activeEditor.focus();

            break;
        }

    }

}

/**
 * Replace only matched node text
 */
function maskInEditor(value) {

    if (!activeEditor) return;

    const walker =
        document.createTreeWalker(
            activeEditor,
            NodeFilter.SHOW_TEXT
        );

    let node;

    while ((node = walker.nextNode())) {

        if (node.nodeValue.includes(value)) {

            node.nodeValue =
                node.nodeValue.replace(
                    value,
                    "XXXXXXXXXXXX"
                );

            break;

        }

    }

    /**
     * Trigger refresh
     */
    activeEditor.dispatchEvent(
        new Event("input", {
            bubbles: true
        })
    );

}

/**
 * Update panel
 */
function updateRiskPanel(detections) {

    const panel =
        createRiskPanel();

    const content =
        document.getElementById(
            "pii-content"
        );

    if (!detections.length) {

        panel.style.display = "none";

        return;
    }

    panel.style.display = "block";

    content.innerHTML = "";

    detections.forEach((item) => {

        const row =
            document.createElement("div");

        row.className =
            `pii-row severity-${item.severity}`;

        row.innerHTML = `
            <div class="pii-info">

                <div class="pii-type">
                    ${item.type}
                </div>

                <div class="pii-value">
                    ${item.value}
                </div>

            </div>

            <div class="pii-actions">

                <button class="pii-btn highlight-btn">
                    Highlight
                </button>

                <button class="pii-btn remove-btn">
                    Mask
                </button>

            </div>
        `;

        /**
         * Highlight
         */
        row.querySelector(
            ".highlight-btn"
        ).addEventListener(
            "click",
            () => {

                highlightInEditor(
                    item.value
                );

            }
        );

        /**
         * Mask
         */
        row.querySelector(
            ".remove-btn"
        ).addEventListener(
            "click",
            () => {

                maskInEditor(
                    item.value
                );

            }
        );

        content.appendChild(row);

    });

}

/**
 * Get text
 */
function getEditorText(el) {

    return el.innerText ||
           el.value ||
           "";

}

/**
 * Setup editor
 */
function setupEditor(editor) {

    if (editor.dataset.piiAttached)
        return;

    editor.dataset.piiAttached =
        "true";

    /**
     * Focus tracking
     */
    editor.addEventListener(
        "focus",
        () => {

            activeEditor = editor;

        }
    );

    /**
     * Analyze
     */
    function analyze() {

        activeEditor = editor;

        const text =
            getEditorText(editor);

        const detections =
            scanPII(text);

        updateRiskPanel(
            detections
        );

    }

    /**
     * Typing
     */
    editor.addEventListener(
        "input",
        () => {

            requestAnimationFrame(
                analyze
            );

        }
    );

    /**
     * Paste
     */
    editor.addEventListener(
        "paste",
        () => {

            setTimeout(
                analyze,
                50
            );

        }
    );

}

/**
 * Detect editors
 */
function detectEditors() {

    const editors =
        document.querySelectorAll(`
            textarea,
            [contenteditable="true"]
        `);

    editors.forEach((editor) => {

        setupEditor(editor);

    });

}

/**
 * Initial scan
 */
detectEditors();

/**
 * Dynamic DOM watcher
 */
const observer =
    new MutationObserver(() => {

        detectEditors();

    });

observer.observe(
    document.body,
    {
        childList: true,
        subtree: true
    }
);