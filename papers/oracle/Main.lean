/-
  `oracle`: reads one case per line (JSON) on stdin, writes the model's verdict per line.

  Case:   {"id", "artifact": a sealed or unsealed .nomos artifact, "facts": {...}}
  Output: {"id", "verdict": "authorized"|"denied"|"escalated"|"incomplete",
           "decider": index among the ruling decisions | null, "rule": its id | null,
           "escalation": string|null}
          or {"id", "error": why the case cannot be evaluated} (e.g. a rule using matches()).

  The oracle reads the artifact's own `when` strings (OracleExpr.lean), so it and an
  implementation read the same text. The verdict is `Oracle.verdict` (OracleCore.lean), proved
  to be the Part II model's. Reading JSON, the tokenizer and the comparison primitives are
  unproved transcriptions of the references.
-/
import Lean.Data.Json
import OracleCore
import OracleExpr

open Lean CarriedAuthority OracleExpr

def trDeny : Kind → Nat | .block => 3 | .esc => 2 | .allow => 1
def trAllow : Kind → Nat | .allow => 3 | .esc => 2 | .block => 1
def trEsc : Kind → Nat | .esc => 3 | .block => 2 | .allow => 1

theorem trDeny_inj : ∀ a b, trDeny a = trDeny b → a = b := by
  intro a b h; cases a <;> cases b <;> simp_all [trDeny]
theorem trAllow_inj : ∀ a b, trAllow a = trAllow b → a = b := by
  intro a b h; cases a <;> cases b <;> simp_all [trAllow]
theorem trEsc_inj : ∀ a b, trEsc a = trEsc b → a = b := by
  intro a b h; cases a <;> cases b <;> simp_all [trEsc]

def optStr (j : Json) (k : String) : Option String :=
  match j.getObjValAs? String k with | .ok s => some s | .error _ => none

def outOf (k : String) (esc : Option String) : Except String (Out String) :=
  match k with
  | "allow" => .ok .allow
  | "block" => .ok .block
  | "escalate" => .ok (.esc (esc.getD ""))
  | k => .error s!"unknown outcome type {k}"

def objKeys (j : Json) : Array String :=
  match j with
  | .obj kvs => kvs.toArray.map (·.1)
  | _ => #[]

def runCase (j : Json) : Except String (Json → Json) := do
  let art ← j.getObjVal? "artifact"
  let facts ← j.getObjVal? "facts"
  let logic ← art.getObjVal? "logic"
  let res := (logic.getObjVal? "resolution").toOption.getD (Json.mkObj [])
  let declared := objKeys (((art.getObjVal? "execution").toOption.bind fun e => (e.getObjVal? "actions").toOption).getD Json.null)
  let all ← logic.getObjValAs? (Array Json) "decisions"
  let isObligation (d : Json) : Bool :=
    match (d.getObjVal? "then").toOption.bind (fun t => (t.getArrVal? 0).toOption) with
    | some t =>
      let ty := optStr t "type"
      ty == some "emit" || (ty == some "action" && (optStr t "action_name").any declared.contains)
    | none => false
  let rulings := all.filter (!isObligation ·)
  let decs ← rulings.mapM fun d => do
    let w ← d.getObjValAs? String "when"
    let c ← compile (← parseString w)
    let t ← (← d.getObjVal? "then").getArrVal? 0
    let o ← outOf (← t.getObjValAs? String "type") (optStr t "escalation_id")
    let p ← d.getObjValAs? Nat "priority"
    pure ({ cond := c, out := o, prio := p } : Dec String Json String)
  let ids := rulings.map fun d => (d.getObjVal? "id").toOption.getD Json.null
  let dflt ← outOf ((optStr res "default_outcome").getD "block") (optStr res "default_escalation_id")
  let inputs := ((art.getObjVal? "data_contract").toOption.bind fun dc => (dc.getObjVal? "inputs").toOption).getD Json.null
  let decided : Array String := #["action_type"] ++ (match inputs with
    | .obj kvs => kvs.toArray.filterMap fun (n, i) =>
        match optStr i "source" with
        | some "action" | some "relying_party" => some n
        | _ => none
    | _ => #[])
  let authF : String → Bool := fun x =>
    decided.contains x || decided.contains ((x.splitOn ".").headD x)
  let F : Facts String Json := fun x => OracleExpr.lookup facts x
  let mk (tr : Kind → Nat) (h : ∀ a b, tr a = tr b → a = b) : Authority String Json String :=
    { n := decs.size, ds := fun i => decs[i], tr := tr, tr_inj := h, dflt := dflt, auth := authF }
  let A ← match (optStr res "tie_breaker").getD "deny_wins" with
    | "deny_wins" => pure (mk trDeny trDeny_inj)
    | "allow_wins" => pure (mk trAllow trAllow_inj)
    | "escalate_wins" => pure (mk trEsc trEsc_inj)
    | t => throw s!"unknown tie_breaker {t}"
  let (v, D) := Oracle.verdict A F
  let (name, esc) : String × Option String := match v with
    | .authorized => ("authorized", none)
    | .denied => ("denied", none)
    | .incomplete => ("incomplete", none)
    | .escalated e => ("escalated", if e == "" then none else some e)
  return fun id => Json.mkObj [("id", id), ("verdict", name),
    ("decider", match D with | some d => toJson d.val | none => Json.null),
    ("rule", match D with | some d => ids[d.val]?.getD Json.null | none => Json.null),
    ("escalation", match esc with | some e => toJson e | none => Json.null)]

def main : IO UInt32 := do
  let stdin ← IO.getStdin
  let stdout ← IO.getStdout
  let mut n := 0
  repeat
    let line ← stdin.getLine
    if line.isEmpty then break
    if line.all Char.isWhitespace then continue
    match Json.parse line with
    | .error e => IO.eprintln s!"line {n}: {e}"; return 1
    | .ok j =>
      let id := (j.getObjVal? "id").toOption.getD Json.null
      match runCase j with
      | .ok out => stdout.putStrLn (out id).compress
      | .error e => stdout.putStrLn (Json.mkObj [("id", id), ("error", e)]).compress
      n := n + 1
  return 0
