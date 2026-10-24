import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import { Maximize2, Plus, CheckCircle2, Sparkles, ShieldAlert } from "lucide-react";
import { GraphCanvas } from "../src/App.jsx";
import "../src/styles.css";

const facts = [{ id: "origin", description: "Test origin" }];
const steps = [];
for (let i = 1; i <= 16; i += 1) {
  facts.push({ id: `f${i}`, description: `s${i.toString().padStart(3, "0")} execution finished: mixed-language fact text used to check wrapping` });
  steps.push({ id: `s${i}`, description: `Test step ${i}：check the endpoint, verify the result, and save evidence`, from: [i === 1 ? "origin" : `f${Math.max(1, Math.floor(i / 2))}`], to: `f${i}`, goal_id: "g001" });
}
const completed = { facts, steps, goals: [{ id: "g001", description: "Finish the test and record the full verification result", status: "completed", from: ["f15", "f16"] }], findings: [] };
const pending = {
  facts: [facts[0]],
  steps: [1, 2, 3].map(i => ({ id: `s${i}`, description: "FullApplicationVerificationThisIsALongUnbrokenDescriptionWithEnglishLongIdentifierThatMustNotOverflow", from: ["origin"], goal_id: "g001", worker: i === 2 ? "test-worker" : null })),
  goals: [{ id: "g001", description: "Collect the test result and return the full verification record", status: "active", from: [] }], findings: [],
};

function Preview() {
  const [mode, setMode] = useState("pending");
  const [layout, setLayout] = useState("dagre_tb");
  const [selected, setSelected] = useState(null);
  return <main style={{ height: "100dvh", display: "flex", flexDirection: "column" }}>
    <header style={{ padding: 8, display: "flex", flexWrap: "wrap", gap: 12, alignItems: "center" }}>
      <label>Test data <select aria-label="Test data" value={mode} onChange={event => { setMode(event.target.value); setSelected(null); }}><option value="pending">Open project</option><option value="completed">17-fact project</option></select></label>
      <output aria-label="Selection">{selected ? `${selected.type}:${selected.id}` : "Nothing selected"}</output>
    </header>
    <section className="graph-panel" style={{ flex: 1 }}>
      <div className="graph-controls">
        <div className="graph-toolbar">
          <button className="ghost-button compact" title="Fit graph" aria-label="Fit graph" onClick={() => window.dispatchEvent(new Event("rabbit:fit-graph"))}><Maximize2 size={16} /></button>
          <select aria-label="Graph layout" value={layout} onChange={event => setLayout(event.target.value)}>
            <option value="dagre_tb">Dagre ↓</option><option value="dagre_lr">Dagre →</option>
            <option value="klay_tb">Klay ↓</option><option value="klay_lr">Klay →</option>
            <option value="elk_tb">ELK ↓</option><option value="elk_lr">ELK →</option>
          </select>
        </div>
        <div className="graph-actions">
          <button className="primary-outline compact"><Plus size={16} />Step</button>
          <button className="primary-outline compact success" disabled><CheckCircle2 size={16} />Complete</button>
          <button className="primary-outline compact warning"><Sparkles size={16} />Hint</button>
          <button className="primary-outline compact"><ShieldAlert size={16} />Conclude</button>
        </div>
      </div>
      <GraphCanvas detail={mode === "pending" ? pending : completed} selected={selected} onSelect={setSelected} layout={layout} />
    </section>
  </main>;
}

createRoot(document.getElementById("root")).render(<Preview />);
