/-
  `oracle`: reads one case per line (JSON) on stdin, writes the model's verdict per line.
  The verdict is `Oracle.verdict` (OracleCore.lean, proved to be the model's). Everything in this
  file, the JSON reading and the comparison primitives, is unproved glue (see OracleCore.lean).

  Case:   {"id", "tie": "deny_wins"|"allow_wins"|"escalate_wins",
           "default": {"kind": "allow"|"block"|"escalate", "esc": string|null},
           "auth": [input names whose absence is authoritative],
           "decisions": [{"cond": C, "kind", "esc": string|null, "prio": nat}],
           "facts": {name: number|string|boolean}}
  C:      {"and": [C, C]} | {"or": [C, C]} | {"not": C} | {"ex": name} | {"bool": name}
        | {"cmp": {"op": "=="|"!="|">"|">="|"<"|"<=", "l": name, "r": {"lit": value} | {"field": name}}}
  Output: {"id", "verdict": "authorized"|"denied"|"escalated"|"incomplete",
           "decider": index|null, "escalation": string|null}
-/
import Lean.Data.Json
import OracleCore

open Lean CarriedAuthority

inductive Val | num (n : Int) | str (s : String) | bool (b : Bool)

def Val.ofJson : Json → Except String Val
  | .num n => if n.exponent == 0 then .ok (.num n.mantissa) else .error "integers only"
  | .str s => .ok (.str s)
  | .bool b => .ok (.bool b)
  | j => .error s!"unsupported value {j.compress}"

/-- Comparison of two present values, as SPEC-008 §6.2 states it: values of different kinds,
    or an ordering of booleans, are outside the primitive's domain (`none`, undecided). -/
def prim (op : String) : Val → Val → Option Bool
  | .num a, .num b => cmpOrd op (compare a b) (a == b)
  | .str a, .str b => cmpOrd op (compare a b) (a == b)
  | .bool a, .bool b => if op == "==" then some (a == b) else if op == "!=" then some (a != b) else none
  | _, _ => none
where
  cmpOrd (op : String) (o : Ordering) (eq : Bool) : Option Bool :=
    match op with
    | "==" => some eq | "!=" => some !eq
    | ">" => some (o == .gt) | ">=" => some (o != .lt)
    | "<" => some (o == .lt) | "<=" => some (o != .gt)
    | _ => none

partial def condOf (j : Json) : Except String (Cond String Val) := do
  if let .ok a := j.getObjVal? "and" then
    return .and (← condOf (← a.getArrVal? 0)) (← condOf (← a.getArrVal? 1))
  if let .ok a := j.getObjVal? "or" then
    return .or (← condOf (← a.getArrVal? 0)) (← condOf (← a.getArrVal? 1))
  if let .ok a := j.getObjVal? "not" then
    return .not (← condOf a)
  if let .ok x := j.getObjValAs? String "ex" then
    return .atom (.ex x)
  if let .ok x := j.getObjValAs? String "bool" then
    return .atom (.cmp [x] fun | [.bool b] => some b | _ => none)
  let c ← j.getObjVal? "cmp"
  let op ← c.getObjValAs? String "op"
  let l ← c.getObjValAs? String "l"
  let r ← c.getObjVal? "r"
  if let .ok y := r.getObjValAs? String "field" then
    return .atom (.cmp [l, y] fun | [a, b] => prim op a b | _ => none)
  let lit ← Val.ofJson (← r.getObjVal? "lit")
  return .atom (.cmp [l] fun | [a] => prim op a lit | _ => none)

def kindOf : String → Except String Kind
  | "allow" => .ok .allow | "block" => .ok .block | "escalate" => .ok .esc
  | k => .error s!"unknown kind {k}"

def outOf (k : String) (esc : Option String) : Except String (Out String) := do
  match ← kindOf k with
  | .allow => return .allow
  | .block => return .block
  | .esc => return .esc (esc.getD "")

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

def runCase (j : Json) : Except String Json := do
  let id ← j.getObjVal? "id"
  let tie ← j.getObjValAs? String "tie"
  let dj ← j.getObjVal? "default"
  let dflt ← outOf (← dj.getObjValAs? String "kind") (optStr dj "esc")
  let auth ← j.getObjValAs? (Array String) "auth"
  let decs ← (← j.getObjValAs? (Array Json) "decisions").mapM fun d => do
    let c ← condOf (← d.getObjVal? "cond")
    let o ← outOf (← d.getObjValAs? String "kind") (optStr d "esc")
    let p ← d.getObjValAs? Nat "prio"
    pure ({ cond := c, out := o, prio := p } : Dec String Val String)
  let fobj ← (← j.getObjVal? "facts").getObj?
  let mut facts : Std.HashMap String Val := {}
  for ⟨k, v⟩ in fobj.toArray do
    facts := facts.insert k (← Val.ofJson v)
  let F : Facts String Val := fun x => facts.get? x
  let authF : String → Bool := fun x => auth.contains x
  let mk (tr : Kind → Nat) (h : ∀ a b, tr a = tr b → a = b) : Authority String Val String :=
    { n := decs.size, ds := fun i => decs[i], tr := tr, tr_inj := h, dflt := dflt, auth := authF }
  let A ← match tie with
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
  return Json.mkObj [("id", id), ("verdict", name),
    ("decider", match D with | some d => toJson d.val | none => Json.null),
    ("escalation", match esc with | some e => toJson e | none => Json.null)]

def main : IO UInt32 := do
  let stdin ← IO.getStdin
  let stdout ← IO.getStdout
  let mut n := 0
  repeat
    let line ← stdin.getLine
    if line.isEmpty then break
    if line.all Char.isWhitespace then continue
    match Json.parse line >>= runCase with
    | .ok out => stdout.putStrLn out.compress; n := n + 1
    | .error e => IO.eprintln s!"case {n}: {e}"; return 1
  return 0
