/-
  The Lean model of Part II run as a test oracle.

  `verdict` is the model's own answer, computed: the deciding decision is `pick`
  (proved to be the decider in Completeness.lean, `pick_isDecider`), and `gateB` is a Boolean
  form of the 0.5.0 gate proved equal to `GateFires` (`gateB_iff` below). So the oracle's
  verdict is the model's verdict by proof, not a third hand-written evaluator.

  What the oracle does not cover: the model leaves primitives abstract (an atom's predicate
  `p : List V → Option Bool`). The comparison semantics given to `p` in Main.lean, and the JSON
  reading, are ordinary unproved code. The oracle checks Kleene logic, the choice of decider,
  the gate and the outcome; parsing and primitives are checked by the published vectors.
-/
import CarriedAuthority
import Completeness

set_option linter.unusedSectionVars false

namespace Oracle
open CarriedAuthority CarriedAuthority.Authority CarriedAuthority.Completeness

variable {I V E : Type} [DecidableEq E] (A : Authority I V E)

def outranksB (X d : Fin A.n) : Bool :=
  decide (A.prio X > A.prio d) || (decide (A.prio X = A.prio d) && decide (A.trk X > A.trk d))

theorem outranksB_iff (X d : Fin A.n) : outranksB A X d = true ↔ A.Outranks X d := by
  simp [outranksB, Authority.Outranks]

def outranksOptB (X : Fin A.n) : Option (Fin A.n) → Bool
  | none => true
  | some d => outranksB A X d

theorem outranksOptB_iff (X : Fin A.n) (D : Option (Fin A.n)) :
    outranksOptB A X D = true ↔ A.OutranksOpt X D := by
  cases D with
  | none => simp [outranksOptB, Authority.OutranksOpt]
  | some d => simp [outranksOptB, Authority.OutranksOpt, outranksB_iff]

def clause2B (X : Fin A.n) : Option (Fin A.n) → Bool
  | none => false
  | some d =>
    match (A.ds d).out, (A.ds X).out with
    | .esc e, .esc e' => decide (e' ≠ e) && decide (A.prio X = A.prio d)
    | _, _ => false

theorem clause2B_iff (X : Fin A.n) (D : Option (Fin A.n)) :
    clause2B A X D = true ↔ A.Clause2 X D := by
  cases D with
  | none => simp [clause2B, Authority.Clause2]
  | some d =>
    unfold clause2B Authority.Clause2
    cases h1 : (A.ds d).out <;> cases h2 : (A.ds X).out <;> simp [h1]

/-- The 0.5.0 gate as a Boolean: some undecided block/escalate decision outranks the decider,
    or meets clause (ii). -/
def gateB (F : Facts I V) (D : Option (Fin A.n)) : Bool :=
  (List.finRange A.n).any fun X =>
    decide (A.val F X = .u) && decide ((A.ds X).out.kind ≠ .allow) &&
      (outranksOptB A X D || clause2B A X D)

theorem gateB_iff (F : Facts I V) (D : Option (Fin A.n)) :
    gateB A F D = true ↔ A.GateFires F D := by
  unfold gateB Authority.GateFires
  simp [List.any_eq_true, List.mem_finRange, outranksOptB_iff, clause2B_iff, and_assoc]

inductive Verdict (E : Type) where
  | authorized
  | denied
  | escalated (e : E)
  | incomplete

/-- The model's verdict: a block is DENIED; otherwise the gate holds the result open, or it
    stands. Returned with the deciding decision (`none`: the default applied). -/
def verdict (F : Facts I V) : Verdict E × Option (Fin A.n) :=
  let D := pick A F
  match A.outcome D with
  | .block => (.denied, D)
  | .allow => (if gateB A F D then .incomplete else .authorized, D)
  | .esc e => (if gateB A F D then .incomplete else .escalated e, D)

theorem verdict_snd (F : Facts I V) : (verdict A F).2 = pick A F := by
  simp only [verdict]; cases A.outcome (pick A F) <;> rfl

/-- `pick` is the decider, so `verdict` reads the model's outcome and gate. -/
theorem verdict_is_model (F : Facts I V) :
    A.IsDecider F (verdict A F).2 ∧
    (∀ e, (verdict A F).1 = .escalated e → ¬ A.GateFires F (verdict A F).2) ∧
    ((verdict A F).1 = .authorized → ¬ A.GateFires F (verdict A F).2) ∧
    ((verdict A F).1 = .incomplete → A.GateFires F (verdict A F).2) := by
  rw [verdict_snd]
  refine ⟨pick_isDecider A F, ?_, ?_, ?_⟩ <;>
  · simp only [verdict]
    cases h : A.outcome (pick A F) <;> cases hg : gateB A F (pick A F) <;>
      simp_all [← gateB_iff]

end Oracle

#print axioms Oracle.gateB_iff
#print axioms Oracle.verdict_is_model
