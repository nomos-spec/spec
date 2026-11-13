/-
  Computable Authority, Part III ("Resolve the Law, Not the Catalogue") and NOMOS-SPEC-014
  (Draft 0.1.0 to 0.4.0; 0.3.0's context fidelity is tested, not modelled): a mechanized model of resolution and the combined verdict, following the
  reference resolver (server/lib/resolution.ts, `resolveApplicableSet` / `combineVerdicts`) step
  by step for ONE query (a context and a time t).

  Self-contained Lean 4 (core only, no Mathlib). Check with:  lean Resolution.lean

  Modelling choices (each is a place to argue):
  * Scope predicates are already evaluated on the query's context: a scope is a Kleene value
    (`K3`). Their three-valued evaluation is NOMOS-SPEC-008's evaluator, proved in Part II.
  * Each authority's own verdict `eval A facts` is taken as given (Part II, per member).
  * The walk over pins and recognition edges is not modelled as a loop: every theorem is stated
    for the list `R` of registrars the walk reached, so "complete" means complete over R.
    `WalkComplete` states what the walk must deliver (every pin, every TRUE edge's target); that
    the resolver's breadth-first walk delivers it is tested in scripts/test-resolution.ts, not
    proved here.
  * Signatures, hashes and heads are not modelled; `World.view` is the registrar state the relying
    party SEES. §6 below shows why that distinction matters.
  * `Rec.closures` are the closures that speak at t: 0.2.0's rule that a later closure over the
    same scope replaces an earlier one is applied before this model (it is tested, not proved).
  * `Checks.full` is SPEC-014 0.1.0 as specified and as first shipped; `Checks.fixed` adds 0.2.0's
    closure agreement. 0.2.0's view-age bound is not modelled (§6).

  Results (§ = section of this file):
  §1  Combination: commutative, associative, order-free; commits iff every member commits.
      The Part III draft's order (ESCALATED above INCOMPLETE) is unsafe (`paper_comb_unsafe`);
      SPEC-014 §4 and the resolver already use the safe order, which is the one proved.
  §3  Sufficiency (`sufficiency`): a commit implies every reached registrar was present, closed
      by a fresh covering closure, had nothing undecided, and every in-force, in-scope claim it
      makes on this context is a member whose verdict commits.
  §4  Containment. More law is never less safe: reaching more registrars (`reached_mono`) or
      adding claims (`add_claim_keeps_law`) never drops a member that was there before.
      C6 protects precision, not safety, in this design: dropping it only adds members
      (`noC6_never_commits_more`), because supersession and revocation act only on a registrar's
      own claims. SPEC-014 §8's "launders a permissive authority" cannot happen.
      C7 IS needed for safety (`C7_necessary_snapshot`), but the published vector ablates it the
      wrong way (ignoring currency altogether only adds members: `noC7_never_commits_more`).
  §5  HOLE 1 — closure contents are never read. A genuine withdrawal hides law while an older
      closure that still lists it stays fresh (`withdrawal_hides_law`). Fix (closure agreement):
      covering closures must agree with the live claims. With it, hiding law requires signing a
      new closure (`hiding_needs_new_closure`) — the SPEC-014 §8 containment claim, now true.
  §6  HOLE 2 — the stale view. A cached registrar state whose closure is still inside its 90-day
      bound resolves to superseded law and commits (`stale_view_commits`). Neither C7 nor C8 as
      specified catches it: SPEC-014 gives the head no timestamp and the relying party no bound
      on its age. The fix (a signed head time and a per-scope bound) is NOT proved here: heads
      are not in the model.
  §7  Necessity of C5, C7 (snapshot) and C8 for safety (genuine artifacts only).
  §8  Deferral (0.4.0): `deferral_never_removes_law` (with or without deferral the resolution is
      the same, except a CONFLICT may become RESOLVED with exactly the laws required without it),
      `deferral_is_own`, `undecided_edge_incomplete`.
  §9  Delegation (0.4.0): `delegation_never_widens` (a delegate's certificate is the edge AND the
      recognizer's, so its law lies where both hold), `delegation_unknown_incomplete`. Fetching
      and verifying logs, key rotation and DNS discovery are tested (registrar-logs.json), not
      modelled.
-/

set_option linter.deprecated false
set_option linter.unusedSectionVars false

namespace Resolution

inductive K3 | f | u | t
  deriving DecidableEq, Repr

/-! ## §1 Verdicts and their strict combination -/

inductive Verdict (E : Type) where
  | authorized
  | denied
  /-- the escalations that must be answered, by name -/
  | escalated (names : E → Bool)
  | incomplete

namespace Verdict
variable {E : Type}

/-- SPEC-014 §4 / `combineVerdicts`: DENIED, then INCOMPLETE, then ESCALATED (union), then
    AUTHORIZED. -/
def comb : Verdict E → Verdict E → Verdict E
  | denied, _ => denied
  | _, denied => denied
  | incomplete, _ => incomplete
  | _, incomplete => incomplete
  | escalated s, escalated s' => escalated (fun e => s e || s' e)
  | escalated s, authorized => escalated s
  | authorized, escalated s => escalated s
  | authorized, authorized => authorized

/-- The combination as the Part III draft (§3.1) words it: ESCALATED before INCOMPLETE. -/
def combPaper : Verdict E → Verdict E → Verdict E
  | denied, _ => denied
  | _, denied => denied
  | escalated s, escalated s' => escalated (fun e => s e || s' e)
  | escalated s, _ => escalated s
  | _, escalated s => escalated s
  | incomplete, _ => incomplete
  | _, incomplete => incomplete
  | authorized, authorized => authorized

/-- What a relying party may commit on, given which escalations people have answered. -/
def Commits (approved : E → Prop) : Verdict E → Prop
  | authorized => True
  | escalated s => ∀ e, s e = true → approved e
  | denied => False
  | incomplete => False

theorem comb_comm (a b : Verdict E) : comb a b = comb b a := by
  cases a <;> cases b <;> simp only [comb]
  case escalated.escalated s s' =>
    congr 1; funext e; exact Bool.or_comm (s e) (s' e)

theorem comb_assoc (a b c : Verdict E) : comb (comb a b) c = comb a (comb b c) := by
  cases a <;> cases b <;> cases c <;> simp only [comb]
  case escalated.escalated.escalated s s' s'' =>
    congr 1; funext e; exact Bool.or_assoc (s e) (s' e) (s'' e)

theorem commits_comb (ap : E → Prop) (a b : Verdict E) :
    Commits ap (comb a b) ↔ Commits ap a ∧ Commits ap b := by
  cases a <;> cases b <;> simp [comb, Commits]
  case escalated.escalated s s' =>
    constructor
    · intro h
      exact ⟨fun e he => h e (Or.inl he), fun e he => h e (Or.inr he)⟩
    · intro ⟨h1, h2⟩ e he
      cases he with
      | inl he => exact h1 e he
      | inr he => exact h2 e he

def combAll (l : List (Verdict E)) : Verdict E := l.foldr comb authorized

theorem commits_combAll (ap : E → Prop) :
    ∀ l : List (Verdict E), Commits ap (combAll l) ↔ ∀ v ∈ l, Commits ap v
  | [] => by simp [combAll, Commits]
  | v :: l => by
    have ih := commits_combAll ap l
    simp only [combAll, List.foldr] at ih ⊢
    rw [commits_comb, ih]
    simp

/-- Order independence: the combined verdict is the same for any order of the members. -/
theorem combAll_perm {l₁ l₂ : List (Verdict E)} (h : l₁.Perm l₂) : combAll l₁ = combAll l₂ := by
  induction h with
  | nil => rfl
  | cons x _ ih => simp only [combAll, List.foldr] at ih ⊢; rw [ih]
  | swap x y l =>
    simp only [combAll, List.foldr]
    rw [← comb_assoc, ← comb_assoc, comb_comm y x]
  | trans _ _ ih₁ ih₂ => exact ih₁.trans ih₂

/-- The draft's order is unsafe: one member INCOMPLETE, another ESCALATED; once the escalation
    is answered the combination commits. -/
theorem paper_comb_unsafe :
    ∃ (a b : Verdict Unit) (ap : Unit → Prop),
      Commits ap (combPaper a b) ∧ ¬ Commits ap a := by
  refine ⟨incomplete, escalated (fun _ => true), fun _ => True, ?_, ?_⟩
  · simp [combPaper, Commits]
  · simp [Commits]

end Verdict

open Verdict

/-! ## §2 Registrar records and the resolver -/

variable {Auth Reg F E : Type} [DecidableEq Auth] [DecidableEq Reg]

/-- `applies`: the claim's scope already evaluated on the query context. Window [start, stop). -/
structure Claim (Auth : Type) where
  auth : Auth
  scope : K3
  excl : Bool
  start : Nat
  stop : Nat

/-- `closed(scope, authorities, signed)`, fresh while `signed ≤ t ≤ signed + maxAge`. -/
structure Closure (Auth : Type) where
  scope : K3
  list : List Auth
  signed : Nat
  maxAge : Nat

/-- A registrar's folded record (`RegistrarRecord`). -/
structure Rec (Reg Auth : Type) where
  cert : K3
  claims : List (Claim Auth)
  closures : List (Closure Auth)
  edges : List (Reg × K3)
  sups : List (Auth × Nat)
  revoked : List Auth

structure World (Reg Auth : Type) where
  view : Reg → Option (Rec Reg Auth)
  pins : List Reg

/-- Which conditions the resolver enforces. `full` is SPEC-014 0.1.0 as specified and shipped;
    `fixed` adds closure agreement (§5). The ablations are the test-only `ablate` modes. -/
structure Checks where
  scope : Bool := true      -- C6
  currency : Bool := true   -- C7
  closure : Bool := true    -- C8
  agree : Bool := false     -- proposed: a covering closure agrees with the live claims
  /-- SPEC-014 0.4.0: a registrar that recognizes another over this context does not assert
      precedence against it (its exclusive claims there raise no CONFLICT with that registrar) -/
  deferral : Bool := false
  /-- C7 dropped the way the paper's zombie attack drops it: membership judged at an earlier
      time (a snapshot), while closure freshness is still judged at t. -/
  snap : Option Nat := none

def Checks.full : Checks := {}
def Checks.fixed : Checks := { agree := true }

inductive Res (Auth : Type) where
  | resolved (S : List Auth)
  | conflict
  | incomplete

section
variable (ck : Checks) (t : Nat)

/-- C7: in its window, not superseded by this registrar at t, not revoked by it. -/
def live (r : Rec Reg Auth) (c : Claim Auth) : Bool :=
  !ck.currency ||
    (decide (c.start ≤ ck.snap.getD t) && decide (ck.snap.getD t < c.stop) &&
      !(r.sups.any fun s => s.1 == c.auth && decide (s.2 ≤ ck.snap.getD t)) &&
      !(r.revoked.contains c.auth))

def fresh (cl : Closure Auth) : Bool := decide (cl.signed ≤ t) && decide (t - cl.signed ≤ cl.maxAge)

def covering (cl : Closure Auth) : Bool := cl.scope == .t && fresh t cl

/-- C6: the registrar's certificate covers the context. -/
def certOK (r : Rec Reg Auth) : Bool := !ck.scope || r.cert == .t

/-- An open context fact anywhere in this registrar's record (certificate, edge, closure scope,
    live claim). -/
def openR (r : Rec Reg Auth) : Bool :=
  r.cert == .u || r.edges.any (fun e => e.2 == .u) ||
    (ck.closure && r.closures.any (fun cl => cl.scope == .u)) ||
    r.claims.any (fun c => live ck t r c && c.scope == .u)

/-- Closure agreement (proposed): no fresh covering closure names an authority this registrar
    does not live-claim, and every claim live and TRUE on this context is named by at least one
    fresh covering closure (a registrar may close several overlapping scopes). -/
def agreeR (r : Rec Reg Auth) : Bool :=
  (r.closures.all fun cl => !covering t cl ||
    cl.list.all fun A => r.claims.any fun c => live ck t r c && c.auth == A) &&
  (r.claims.all fun c => !(live ck t r c && c.scope == .t) ||
    r.closures.any fun cl => covering t cl && cl.list.contains c.auth)

/-- This registrar holds the resolution open: missing (C8), uncovered (C8), an open fact, or
    (fixed) a closure that disagrees with its claims. -/
def regBad : Option (Rec Reg Auth) → Bool
  | none => ck.closure
  | some r => openR ck t r || (ck.closure && !(r.closures.any (covering t))) ||
      (ck.agree && !agreeR ck t r)

/-- The claims this registrar contributes as members. -/
def cands : Option (Rec Reg Auth) → List (Claim Auth)
  | none => []
  | some r => r.claims.filter fun c => live ck t r c && c.scope == .t && certOK ck r

def allCands (w : World Reg Auth) (R : List Reg) : List (Reg × Claim Auth) :=
  R.flatMap fun r => (cands ck t (w.view r)).map fun c => (r, c)

/-- `a` defers to `b` on this context: `a`'s OWN log carries a recognition edge to `b` whose scope
    is TRUE here. (An undecided edge scope already holds the resolution open via `openR`.) -/
def defersTo (w : World Reg Auth) (a b : Reg) : Bool :=
  match w.view a with
  | none => false
  | some r => r.edges.any fun e => e.1 == b && e.2 == .t

/-- CONFLICT: exclusive member claims from two different registrars, neither deferring to the
    other (when deferral is on). -/
def conflictB (w : World Reg Auth) (R : List Reg) : Bool :=
  (allCands ck t w R).any fun x => x.2.excl &&
    (allCands ck t w R).any fun y => y.2.excl && x.1 != y.1 &&
      !(ck.deferral && (defersTo w x.1 y.1 || defersTo w y.1 x.1))

/-- `resolveApplicableSet` over the reached registrars R. Precedence INCOMPLETE > CONFLICT. -/
def resolve (w : World Reg Auth) (R : List Reg) : Res Auth :=
  if R.any (fun r => regBad ck t (w.view r)) then .incomplete
  else if conflictB ck t w R then .conflict
  else .resolved ((allCands ck t w R).map fun x => x.2.auth)
end

/-- What the walk must deliver: every pin, and every registrar a TRUE edge of a present reached
    registrar points to. (The resolver's breadth-first walk; tested, not modelled here.) -/
def WalkComplete (w : World Reg Auth) (R : List Reg) : Prop :=
  (∀ p ∈ w.pins, p ∈ R) ∧
  ∀ r ∈ R, ∀ rec, w.view r = some rec → ∀ e ∈ rec.edges, e.2 = .t → e.1 ∈ R

structure Act (Auth F : Type) where
  presented : List Auth
  facts : F

def decideWith (ck : Checks) (t : Nat) (eval : Auth → F → Verdict E) (w : World Reg Auth)
    (R : List Reg) (α : Act Auth F) : Verdict E :=
  match resolve ck t w R with
  | .resolved S => combAll (S.map fun A => eval A α.facts)
  | .conflict => .incomplete   -- surfaced to people; the machine never commits on it
  | .incomplete => .incomplete

/-- The C5 ablation: take the set from the Act. -/
def decideNaive (eval : Auth → F → Verdict E) (α : Act Auth F) : Verdict E :=
  combAll (α.presented.map fun A => eval A α.facts)

/-- C5 is architectural: the Act's list is not an argument of `resolve`. -/
theorem decide_ignores_presented (ck : Checks) (t : Nat) (eval : Auth → F → Verdict E)
    (w : World Reg Auth) (R : List Reg) (α : Act Auth F) (p : List Auth) :
    decideWith ck t eval w R { α with presented := p } = decideWith ck t eval w R α := rfl

/-! ## §3 Sufficiency -/

theorem mem_allCands {ck : Checks} {t : Nat} {w : World Reg Auth} {R : List Reg}
    {x : Reg × Claim Auth} : x ∈ allCands ck t w R ↔ x.1 ∈ R ∧ x.2 ∈ cands ck t (w.view x.1) := by
  unfold allCands
  constructor
  · intro h
    obtain ⟨r, hr, h⟩ := List.mem_flatMap.mp h
    obtain ⟨c, hc, rfl⟩ := List.mem_map.mp h
    exact ⟨hr, hc⟩
  · intro ⟨hr, hc⟩
    exact List.mem_flatMap.mpr ⟨x.1, hr, List.mem_map.mpr ⟨x.2, hc, rfl⟩⟩

theorem mem_cands {ck : Checks} {t : Nat} {rec : Rec Reg Auth} {c : Claim Auth} :
    c ∈ cands ck t (some rec) ↔
      c ∈ rec.claims ∧ live ck t rec c = true ∧ c.scope = .t ∧ certOK ck rec = true := by
  simp [cands, List.mem_filter, Bool.and_eq_true, beq_iff_eq, and_assoc]

theorem sufficiency (ck : Checks) (t : Nat) (ap : E → Prop) (eval : Auth → F → Verdict E)
    (w : World Reg Auth) (R : List Reg) (α : Act Auth F)
    (h : Commits ap (decideWith ck t eval w R α)) :
    ∃ S, resolve ck t w R = .resolved S ∧
      (∀ r ∈ R, regBad ck t (w.view r) = false) ∧
      conflictB ck t w R = false ∧
      (∀ x, x ∈ allCands ck t w R → x.2.auth ∈ S) ∧
      (∀ A ∈ S, ∃ x, x ∈ allCands ck t w R ∧ x.2.auth = A) ∧
      (∀ A ∈ S, Commits ap (eval A α.facts)) := by
  unfold decideWith at h
  unfold resolve at h ⊢
  by_cases hb : (R.any fun r => regBad ck t (w.view r)) = true
  · rw [if_pos hb] at h; exact absurd h (by simp [Commits])
  · rw [if_neg hb] at h ⊢
    by_cases hx : conflictB ck t w R = true
    · rw [if_pos hx] at h; exact absurd h (by simp [Commits])
    · rw [if_neg hx] at h ⊢
      refine ⟨_, rfl, ?_, by simpa using hx, ?_, ?_, ?_⟩
      · intro r hr
        cases hrb : regBad ck t (w.view r)
        · rfl
        · exact absurd (List.any_eq_true.mpr ⟨r, hr, hrb⟩) hb
      · intro x hxm; exact List.mem_map.mpr ⟨x, hxm, rfl⟩
      · intro A hA
        obtain ⟨x, hxm, rfl⟩ := List.mem_map.mp hA
        exact ⟨x, hxm, rfl⟩
      · intro A hA
        exact ((commits_combAll ap _).mp h) _ (List.mem_map.mpr ⟨A, hA, rfl⟩)

/-- The full resolver, spelled out: a commit means every reached registrar was present, has a
    fresh covering closure and nothing undecided, and every claim it makes that is live, TRUE on
    the context and within its certificate names an authority whose verdict commits. -/
theorem full_commit (t : Nat) (ap : E → Prop) (eval : Auth → F → Verdict E)
    (w : World Reg Auth) (R : List Reg) (α : Act Auth F)
    (h : Commits ap (decideWith Checks.full t eval w R α)) :
    ∀ r ∈ R, ∃ rec, w.view r = some rec ∧
      rec.closures.any (covering t) = true ∧ openR Checks.full t rec = false ∧
      ∀ c ∈ rec.claims, live Checks.full t rec c = true → c.scope = .t → rec.cert = .t →
        Commits ap (eval c.auth α.facts) := by
  obtain ⟨S, _, hbad, _, hall, _, hmem⟩ := sufficiency _ t ap eval w R α h
  intro r hr
  have hb := hbad r hr
  cases hrec : w.view r with
  | none => rw [hrec] at hb; simp [regBad, Checks.full] at hb
  | some rec =>
    rw [hrec] at hb
    have hopen : openR Checks.full t rec = false := by
      cases ho : openR Checks.full t rec
      · rfl
      · simp [regBad, ho] at hb
    have hcov : rec.closures.any (covering t) = true := by
      cases hc : rec.closures.any (covering t)
      · simp [regBad, Checks.full, hc] at hb
      · rfl
    refine ⟨rec, rfl, hcov, hopen, ?_⟩
    · intro c hc hl hs hcert
      apply hmem
      apply hall (r, c)
      refine mem_allCands.mpr ⟨hr, ?_⟩
      rw [hrec]
      exact mem_cands.mpr ⟨hc, hl, hs, by simp [certOK, Checks.full, hcert]⟩

/-! ## §4 Containment: more law is never less safe -/

/-- Deferral under (ck', w') is no wider than under (ck, w). -/
def DefersNoMore (ck ck' : Checks) (w w' : World Reg Auth) : Prop :=
  ∀ a b, (ck'.deferral && defersTo w' a b) = true → (ck.deferral && defersTo w a b) = true

theorem conflict_mono {ck ck' : Checks} {t : Nat} {w w' : World Reg Auth} {R R' : List Reg}
    (hsub : ∀ x, x ∈ allCands ck t w R → x ∈ allCands ck' t w' R')
    (hdef : DefersNoMore ck ck' w w')
    (h : conflictB ck t w R = true) : conflictB ck' t w' R' = true := by
  unfold conflictB at h ⊢
  obtain ⟨x, hx, h⟩ := List.any_eq_true.mp h
  simp only [Bool.and_eq_true] at h
  obtain ⟨y, hy, hy'⟩ := List.any_eq_true.mp h.2
  simp only [Bool.and_eq_true, Bool.not_eq_true'] at hy'
  refine List.any_eq_true.mpr ⟨x, hsub x hx, ?_⟩
  simp only [Bool.and_eq_true]
  refine ⟨h.1, List.any_eq_true.mpr ⟨y, hsub y hy, ?_⟩⟩
  simp only [Bool.and_eq_true, Bool.not_eq_true']
  refine ⟨hy'.1, ?_⟩
  cases hc : (ck'.deferral && (defersTo w' x.1 y.1 || defersTo w' y.1 x.1))
  · rfl
  · exfalso
    simp only [Bool.and_eq_true, Bool.or_eq_true] at hc
    obtain ⟨hd', h2⟩ := hc
    have key : ∀ a b, defersTo w' a b = true → ck.deferral = true ∧ defersTo w a b = true := fun a b hab => by
      have := hdef a b (by rw [hd', hab]; rfl)
      simpa only [Bool.and_eq_true] using this
    rcases h2 with h2 | h2
    · obtain ⟨k1, k2⟩ := key _ _ h2; rw [k1, k2] at hy'; simp at hy'
    · obtain ⟨k1, k2⟩ := key _ _ h2; rw [k1, k2] at hy'; simp at hy'

/-- General containment: if every reason to hold the resolution open under (ck, w, R) is also
    one under (ck', w', R'), and every member there is a member here, a commit there is a commit
    here. -/
theorem stricter_safe {ck ck' : Checks} {t : Nat} (ap : E → Prop) (eval : Auth → F → Verdict E)
    {w w' : World Reg Auth} {R R' : List Reg} (α : Act Auth F)
    (hbad : (∀ r ∈ R', regBad ck' t (w'.view r) = false) → ∀ r ∈ R, regBad ck t (w.view r) = false)
    (hc : ∀ x, x ∈ allCands ck t w R → x ∈ allCands ck' t w' R')
    (hdef : DefersNoMore ck ck' w w')
    (h : Commits ap (decideWith ck' t eval w' R' α)) :
    Commits ap (decideWith ck t eval w R α) := by
  obtain ⟨S', _, hb', hx', hall', _, hmem'⟩ := sufficiency ck' t ap eval w' R' α h
  have hb := hbad hb'
  have hnb : (R.any fun r => regBad ck t (w.view r)) = false := by
    cases hh : R.any fun r => regBad ck t (w.view r)
    · rfl
    · obtain ⟨r, hr, hrb⟩ := List.any_eq_true.mp hh
      rw [hb r hr] at hrb; cases hrb
  have hnx : conflictB ck t w R = false := by
    cases hh : conflictB ck t w R
    · rfl
    · rw [conflict_mono hc hdef hh] at hx'; cases hx'
  unfold decideWith resolve
  rw [hnb, hnx]
  simp only [Bool.false_eq_true, ↓reduceIte]
  apply (commits_combAll ap _).mpr
  intro v hv
  obtain ⟨A, hA, rfl⟩ := List.mem_map.mp hv
  obtain ⟨x, hxm, rfl⟩ := List.mem_map.mp hA
  exact hmem' _ (hall' x (hc x hxm))

/-- Reaching more registrars (more pins, more recognition edges) is never less safe. -/
theorem reached_mono (ck : Checks) (t : Nat) (ap : E → Prop) (eval : Auth → F → Verdict E)
    (w : World Reg Auth) {R R' : List Reg} (hsub : ∀ r ∈ R, r ∈ R') (α : Act Auth F)
    (h : Commits ap (decideWith ck t eval w R' α)) : Commits ap (decideWith ck t eval w R α) :=
  stricter_safe ap eval α (fun hb r hr => hb r (hsub r hr))
    (fun x hx => mem_allCands.mpr ⟨hsub _ (mem_allCands.mp hx).1, (mem_allCands.mp hx).2⟩) (fun _ _ h => h) h

def addClaim (w : World Reg Auth) (r₀ : Reg) (c₀ : Claim Auth) : World Reg Auth :=
  { w with view := fun r => if r = r₀ then (w.view r).map fun rec => { rec with claims := rec.claims ++ [c₀] }
                           else w.view r }

/-- An extra applicability claim, from any key, never removes a member: if the relying party
    commits with it, every member it had without it was checked and commits. (Under `fixed`
    the extra claim can also complete an agreement, so this is the form that holds for both.) -/
theorem add_claim_keeps_law (ck : Checks) (t : Nat) (ap : E → Prop) (eval : Auth → F → Verdict E)
    (w : World Reg Auth) (R : List Reg) (r₀ : Reg) (c₀ : Claim Auth) (α : Act Auth F)
    (h : Commits ap (decideWith ck t eval (addClaim w r₀ c₀) R α)) :
    ∀ x ∈ allCands ck t w R, Commits ap (eval x.2.auth α.facts) := by
  obtain ⟨_, _, _, _, hall, _, hmem⟩ := sufficiency ck t ap eval _ R α h
  intro x hx
  apply hmem; apply hall
  obtain ⟨hr, hc⟩ := mem_allCands.mp hx
  refine mem_allCands.mpr ⟨hr, ?_⟩
  unfold addClaim; dsimp only
  cases hrec : w.view x.1 with
  | none => rw [hrec] at hc; simp [cands] at hc
  | some rec =>
    rw [hrec] at hc
    obtain ⟨hcm, hl, hs, hcert⟩ := mem_cands.mp hc
    by_cases he : x.1 = r₀
    · rw [if_pos he]
      dsimp only [Option.map]
      exact mem_cands.mpr ⟨List.mem_append_left _ hcm, by simpa [live] using hl, hs, by simpa [certOK] using hcert⟩
    · rw [if_neg he]; exact hc

/-- Dropping C6 only ever adds members: it can cause a wrongful refusal, never a commit the full
    resolver would refuse. -/
theorem noC6_never_commits_more (t : Nat) (ap : E → Prop) (eval : Auth → F → Verdict E)
    (w : World Reg Auth) (R : List Reg) (α : Act Auth F)
    (h : Commits ap (decideWith { scope := false } t eval w R α)) :
    Commits ap (decideWith Checks.full t eval w R α) := by
  apply stricter_safe ap eval α _ _ (fun _ _ h => by simp [Checks.full] at h) h
  · intro hb r hr
    have e : regBad Checks.full t (w.view r) = regBad { scope := false } t (w.view r) := by
      cases w.view r <;> rfl
    rw [e]; exact hb r hr
  · intro x hx
    obtain ⟨hr, hc⟩ := mem_allCands.mp hx
    refine mem_allCands.mpr ⟨hr, ?_⟩
    cases hrec : w.view x.1 with
    | none => rw [hrec] at hc; simp [cands] at hc
    | some rec =>
      rw [hrec] at hc
      obtain ⟨hcm, hl, hs, _⟩ := mem_cands.mp hc
      have e : live { scope := false } t rec x.2 = live Checks.full t rec x.2 := rfl
      exact mem_cands.mpr ⟨hcm, e ▸ hl, hs, by simp [certOK]⟩

/-- Dropping C7 the way the SPEC-014 vector ablates it (windows, supersession and revocation
    ignored altogether) only ever adds members, so that ablation cannot show C7 is needed for
    safety. `C7_necessary_snapshot` below is the ablation that does. -/
theorem noC7_never_commits_more (t : Nat) (ap : E → Prop) (eval : Auth → F → Verdict E)
    (w : World Reg Auth) (R : List Reg) (α : Act Auth F)
    (h : Commits ap (decideWith { currency := false } t eval w R α)) :
    Commits ap (decideWith Checks.full t eval w R α) := by
  apply stricter_safe ap eval α _ _ (fun _ _ h => by simp [Checks.full] at h) h
  · intro hb r hr; have := hb r hr
    cases hrec : w.view r with
    | none => rw [hrec] at this; simpa [regBad, Checks.full] using this
    | some rec =>
      rw [hrec] at this
      simp only [regBad, openR, Checks.full, Bool.or_eq_false_iff, Bool.not_true, Bool.false_and,
        Bool.and_false, Bool.true_and, Bool.or_false, Bool.false_or, live, Bool.not_false,
        Bool.true_or, List.any_eq_false, Bool.and_eq_true, beq_iff_eq] at this ⊢
      refine ⟨⟨⟨this.1.1.1, this.1.1.2⟩, ?_⟩, this.2⟩
      · intro c hc ⟨_, hu⟩; exact this.1.2 c hc hu
  · intro x hx
    obtain ⟨hr, hc⟩ := mem_allCands.mp hx
    refine mem_allCands.mpr ⟨hr, ?_⟩
    cases hrec : w.view x.1 with
    | none => rw [hrec] at hc; simp [cands] at hc
    | some rec =>
      rw [hrec] at hc
      obtain ⟨hcm, _, hs, hcert⟩ := mem_cands.mp hc
      exact mem_cands.mpr ⟨hcm, by simp [live], hs, by simpa [certOK, Checks.full] using hcert⟩

/-! ## §5 Hole 1: closure contents are never read — and the fix -/

/-- With closure agreement, every authority a fresh covering closure lists has a live claim at
    commit time. So law named in the registrar's own current closure cannot be dropped by a
    withdrawal, a supersession or a revocation alone: hiding it requires signing a new closure
    that omits it — attributable, in the chain forever. -/
theorem hiding_needs_new_closure (t : Nat) (ap : E → Prop) (eval : Auth → F → Verdict E)
    (w : World Reg Auth) (R : List Reg) (α : Act Auth F)
    (h : Commits ap (decideWith Checks.fixed t eval w R α)) :
    ∀ r ∈ R, ∀ rec, w.view r = some rec → ∀ cl ∈ rec.closures, covering t cl = true →
      ∀ A ∈ cl.list, ∃ c ∈ rec.claims, live Checks.fixed t rec c = true ∧ c.auth = A := by
  obtain ⟨_, _, hbad, _⟩ := sufficiency _ t ap eval w R α h
  intro r hr rec hrec cl hcl hcov A hA
  have hb := hbad r hr
  rw [hrec] at hb
  simp only [regBad, Checks.fixed, Bool.or_eq_false_iff, Bool.true_and, Bool.not_eq_false'] at hb
  simp only [agreeR, Bool.and_eq_true] at hb
  have hag := List.all_eq_true.mp hb.2.1 cl hcl
  rw [hcov] at hag
  simp only [Bool.not_true, Bool.false_or, List.all_eq_true] at hag
  obtain ⟨c, hc, hc'⟩ := List.any_eq_true.mp (hag A hA)
  simp only [Bool.and_eq_true, beq_iff_eq] at hc'
  exact ⟨c, hc, hc'.1, hc'.2⟩

/-! ## A small world for the counterexamples

  A payment relying party honours its own policy and a sanctions régime. On these facts the
  policy authorizes and the sanctions authority denies. -/

inductive A | policy | sanctions | sanctionsOld
  deriving DecidableEq, Repr

inductive Rg | own | sanctionsReg
  deriving DecidableEq, Repr

def evalEx : A → Unit → Verdict Unit
  | .policy, _ => .authorized
  | .sanctions, _ => .denied
  | .sanctionsOld, _ => .authorized

def apNone : Unit → Prop := fun _ => False
def actEx : Act A Unit := { presented := [.policy], facts := () }
def R2 : List Rg := [.own, .sanctionsReg]

def ownRec : Rec Rg A :=
  { cert := .t, claims := [⟨.policy, .t, false, 0, 1000⟩],
    closures := [⟨.t, [.policy], 40, 90⟩], edges := [], sups := [], revoked := [] }

def sanctionsRec : Rec Rg A :=
  { cert := .t, claims := [⟨.sanctions, .t, false, 0, 1000⟩],
    closures := [⟨.t, [.sanctions], 40, 90⟩], edges := [], sups := [], revoked := [] }

def world0 : World Rg A :=
  { view := fun r => match r with | .own => some ownRec | .sanctionsReg => some sanctionsRec,
    pins := R2 }

theorem world0_full : decideWith Checks.full 50 evalEx world0 R2 actEx = .denied := rfl
theorem world0_fixed : decideWith Checks.fixed 50 evalEx world0 R2 actEx = .denied := rfl

/-- Hole 1. The sanctions registrar's claim is withdrawn at 45 (a genuine `withdrawn` entry — or
    a compromised key's). Its closure signed at 40 still lists the sanctions authority and is
    still inside its 90-day bound. The shipped resolver reads only the closure's freshness, so
    the sanctions authority silently drops out and the payment commits. Closure agreement holds
    it open instead. -/
def worldWithdrawn : World Rg A :=
  { world0 with view := fun r => match r with
      | .own => some ownRec
      | .sanctionsReg => some { sanctionsRec with claims := [⟨.sanctions, .t, false, 0, 45⟩] } }

theorem withdrawal_hides_law :
    Commits apNone (decideWith Checks.full 50 evalEx worldWithdrawn R2 actEx) ∧
    ¬ Commits apNone (decideWith Checks.fixed 50 evalEx worldWithdrawn R2 actEx) := by
  refine ⟨?_, ?_⟩
  · show Commits apNone (Verdict.authorized); trivial
  · show ¬ Commits apNone (Verdict.incomplete); exact id

/-! ## §6 Hole 2: the stale view -/

/-- The sanctions registrar's true state at t = 50: the old authority was superseded at 45 by the
    stricter one, and a new closure signed at 45 lists it. -/
def sanctionsTrue : Rec Rg A :=
  { cert := .t,
    claims := [⟨.sanctionsOld, .t, false, 0, 1000⟩, ⟨.sanctions, .t, false, 45, 1000⟩],
    closures := [⟨.t, [.sanctionsOld], 10, 90⟩, ⟨.t, [.sanctions], 45, 90⟩],
    edges := [], sups := [(.sanctionsOld, 45)], revoked := [] }

/-- What a relying party (or its resolver) that cached the log at 20 sees: genuine entries, a
    closure still inside its bound. -/
def sanctionsCached : Rec Rg A :=
  { cert := .t, claims := [⟨.sanctionsOld, .t, false, 0, 1000⟩],
    closures := [⟨.t, [.sanctionsOld], 10, 90⟩], edges := [], sups := [], revoked := [] }

def worldTrue : World Rg A :=
  { world0 with view := fun r => match r with | .own => some ownRec | .sanctionsReg => some sanctionsTrue }
def worldCached : World Rg A :=
  { world0 with view := fun r => match r with | .own => some ownRec | .sanctionsReg => some sanctionsCached }

/-- Hole 2. On the true log the payment is refused; on a cached copy whose closure is still
    "fresh", the full resolver — and the fixed one, since the cached copy agrees with itself —
    commits under superseded law. Membership is judged at t (C7) and the closure is in bound
    (C8), so neither condition as specified catches it. The log head needs its own freshness
    bound, set by the relying party per scope. -/
theorem stale_view_commits :
    ¬ Commits apNone (decideWith Checks.full 50 evalEx worldTrue R2 actEx) ∧
    Commits apNone (decideWith Checks.full 50 evalEx worldCached R2 actEx) ∧
    Commits apNone (decideWith Checks.fixed 50 evalEx worldCached R2 actEx) := by
  refine ⟨?_, ?_, ?_⟩
  · show ¬ Commits apNone (Verdict.denied); exact id
  · show Commits apNone (Verdict.authorized); trivial
  · show Commits apNone (Verdict.authorized); trivial

/-! ## §7 Necessity of C5, C7 and C8 for safety -/

/-- C7, snapshot: the sanctions registrar superseded the old authority at 45 and closed over the
    new one at 45 (fresh at t = 50). A resolver that judges membership at 20 keeps the old,
    permissive authority and drops the new one; the full resolver refuses. -/
def sanctionsSwitched : Rec Rg A :=
  { cert := .t,
    claims := [⟨.sanctionsOld, .t, false, 0, 1000⟩, ⟨.sanctions, .t, false, 45, 1000⟩],
    closures := [⟨.t, [.sanctions], 45, 90⟩],
    edges := [], sups := [(.sanctionsOld, 45)], revoked := [] }

def worldSwitched : World Rg A :=
  { world0 with view := fun r => match r with | .own => some ownRec | .sanctionsReg => some sanctionsSwitched }

theorem C7_necessary_snapshot :
    Commits apNone (decideWith { snap := some 20 } 50 evalEx worldSwitched R2 actEx) ∧
    ¬ Commits apNone (decideWith Checks.full 50 evalEx worldSwitched R2 actEx) := by
  refine ⟨?_, ?_⟩
  · show Commits apNone (Verdict.authorized); trivial
  · show ¬ Commits apNone (Verdict.denied); exact id

/-- C5: trusting the Act's own list commits the sanctioned payment. -/
theorem C5_necessary :
    Commits apNone (decideNaive evalEx actEx) ∧
    ¬ Commits apNone (decideWith Checks.full 50 evalEx world0 R2 actEx) := by
  refine ⟨trivial, ?_⟩
  rw [world0_full]; exact id

/-- C8, unreachable: no one lies; the sanctions registrar is missing from the view. -/
def worldStarved : World Rg A :=
  { world0 with view := fun r => match r with | .own => some ownRec | .sanctionsReg => none }

theorem C8_necessary_unreachable :
    Commits apNone (decideWith { closure := false } 50 evalEx worldStarved R2 actEx) ∧
    ¬ Commits apNone (decideWith Checks.full 50 evalEx worldStarved R2 actEx) := by
  refine ⟨?_, ?_⟩
  · show Commits apNone (Verdict.authorized); trivial
  · show ¬ Commits apNone (Verdict.incomplete); exact id

/-- C8, stale closure: the sanctions registrar's only closure is past its bound and its claim
    has lapsed; without C8 absence is read as inapplicability. -/
def sanctionsStale : Rec Rg A :=
  { sanctionsRec with claims := [⟨.sanctions, .t, false, 0, 20⟩], closures := [⟨.t, [.sanctions], 0, 30⟩] }

def worldStale : World Rg A :=
  { world0 with view := fun r => match r with
      | .own => some ownRec
      | .sanctionsReg => some sanctionsStale }

theorem C8_necessary_stale :
    Commits apNone (decideWith { closure := false } 50 evalEx worldStale R2 actEx) ∧
    ¬ Commits apNone (decideWith Checks.full 50 evalEx worldStale R2 actEx) := by
  refine ⟨?_, ?_⟩
  · show Commits apNone (Verdict.authorized); trivial
  · show ¬ Commits apNone (Verdict.incomplete); exact id

/-! ## §8 Deferral (SPEC-014 0.4.0): a recognition edge dissolves a conflict, and removes nothing -/

/-- The set of required laws does not read `deferral`. -/
theorem allCands_deferral (ck : Checks) (t : Nat) (w : World Reg Auth) (R : List Reg) :
    allCands { ck with deferral := true } t w R = allCands { ck with deferral := false } t w R := rfl

theorem regBad_deferral (ck : Checks) (t : Nat) (o : Option (Rec Reg Auth)) :
    regBad { ck with deferral := true } t o = regBad { ck with deferral := false } t o := by
  cases o <;> rfl

/-- Deferral never removes a law. With or without it, the resolution is the same, except that a
    CONFLICT may become RESOLVED, and then with exactly the laws the resolver without deferral
    would have required. -/
theorem deferral_never_removes_law (ck : Checks) (t : Nat) (w : World Reg Auth) (R : List Reg) :
    resolve { ck with deferral := true } t w R = resolve { ck with deferral := false } t w R ∨
    (resolve { ck with deferral := false } t w R = .conflict ∧
     resolve { ck with deferral := true } t w R =
       .resolved ((allCands { ck with deferral := false } t w R).map fun x => x.2.auth)) := by
  unfold resolve
  have hb : (R.any fun r => regBad { ck with deferral := true } t (w.view r)) =
      (R.any fun r => regBad { ck with deferral := false } t (w.view r)) := by
    congr 1
  rw [hb, allCands_deferral]
  by_cases h1 : (R.any fun r => regBad { ck with deferral := false } t (w.view r)) = true
  · left; simp [h1]
  · simp only [h1, Bool.false_eq_true, if_false]
    by_cases h0 : conflictB { ck with deferral := false } t w R = true
    · by_cases hd : conflictB { ck with deferral := true } t w R = true
      · left; simp [h0, hd]
      · right; simp [h0, hd]
    · have hd : conflictB { ck with deferral := true } t w R = false := by
        cases hd : conflictB { ck with deferral := true } t w R
        · rfl
        · exfalso; apply h0
          unfold conflictB at hd ⊢
          rw [allCands_deferral] at hd
          obtain ⟨x, hx, hx'⟩ := List.any_eq_true.mp hd
          simp only [Bool.and_eq_true] at hx'
          obtain ⟨y, hy, hy'⟩ := List.any_eq_true.mp hx'.2
          simp only [Bool.and_eq_true] at hy'
          refine List.any_eq_true.mpr ⟨x, hx, ?_⟩
          simp only [Bool.and_eq_true]
          refine ⟨hx'.1, List.any_eq_true.mpr ⟨y, hy, ?_⟩⟩
          simp only [Bool.and_eq_true]
          exact ⟨⟨hy'.1.1, hy'.1.2⟩, by simp⟩
      left; simp [h0, hd]

/-- Only a registrar's own log can waive its precedence: whether `a` defers to `b` reads `a`'s
    record and nothing else. -/
theorem deferral_is_own (w w' : World Reg Auth) (a b : Reg) (h : w.view a = w'.view a) :
    defersTo w a b = defersTo w' a b := by
  unfold defersTo; rw [h]

/-- An unknown fact keeps the conflict open: a reached registrar whose recognition edge has an
    undecided scope holds the resolution INCOMPLETE, deferral or not. -/
theorem undecided_edge_incomplete (ck : Checks) (t : Nat) (w : World Reg Auth) (R : List Reg)
    (r : Reg) (hr : r ∈ R) (rec : Rec Reg Auth) (hv : w.view r = some rec)
    (e : Reg × K3) (he : e ∈ rec.edges) (hu : e.2 = .u) : resolve ck t w R = .incomplete := by
  unfold resolve
  have : (R.any fun r => regBad ck t (w.view r)) = true := by
    refine List.any_eq_true.mpr ⟨r, hr, ?_⟩
    rw [hv]; unfold regBad openR
    have : rec.edges.any (fun e => e.2 == .u) = true := List.any_eq_true.mpr ⟨e, he, by simp [hu]⟩
    simp [this]
  simp [this]

/-! ## §9 Delegation (SPEC-014 0.4.0): a recognized registrar holds no more than was delegated -/

/-- Kleene conjunction, the `and` of SPEC-008 conditions. -/
def K3.and3 : K3 → K3 → K3
  | .f, _ => .f
  | _, .f => .f
  | .t, .t => .t
  | _, _ => .u

/-- A delegate's certificate, as a resolver derives it from a recognition entry that names the
    delegate's key: the edge's scope AND the recognizing registrar's own certificate. Nothing the
    delegate's own log says enters it. -/
def delegate (parent : Rec Reg Auth) (edge : K3) (child : Rec Reg Auth) : Rec Reg Auth :=
  { child with cert := K3.and3 edge parent.cert }

/-- Delegation never widens: any law a delegate contributes lies where the recognizing registrar's
    own certificate holds and where the recognition edge holds. A registrar certified for one place
    cannot, by recognizing another, import law into a place it does not cover. -/
theorem delegation_never_widens (ck : Checks) (t : Nat) (parent child : Rec Reg Auth) (edge : K3)
    (hs : ck.scope = true) (c : Claim Auth) (hc : c ∈ cands ck t (some (delegate parent edge child))) :
    parent.cert = .t ∧ edge = .t := by
  unfold cands at hc
  have h := (List.mem_filter.mp hc).2
  simp only [certOK, hs, delegate, Bool.not_true, Bool.false_or, Bool.and_eq_true, beq_iff_eq] at h
  have hk := h.2
  cases edge <;> cases hp : parent.cert <;> simp_all [K3.and3]

/-- An unknown fact on the delegation keeps the resolution open: if the edge's scope is undecided
    and the recognizer's certificate does not exclude the context, the delegate holds the
    resolution INCOMPLETE. -/
theorem delegation_unknown_incomplete (ck : Checks) (t : Nat) (parent child : Rec Reg Auth)
    (hp : parent.cert ≠ .f) :
    regBad ck t (some (delegate parent .u child)) = true := by
  have hc : K3.and3 .u parent.cert = .u := by cases h : parent.cert <;> simp_all [K3.and3]
  simp [regBad, openR, delegate, hc]

end Resolution

#print axioms Resolution.sufficiency
#print axioms Resolution.full_commit
#print axioms Resolution.stricter_safe
#print axioms Resolution.noC6_never_commits_more
#print axioms Resolution.noC7_never_commits_more
#print axioms Resolution.hiding_needs_new_closure
#print axioms Resolution.withdrawal_hides_law
#print axioms Resolution.stale_view_commits
#print axioms Resolution.C7_necessary_snapshot
#print axioms Resolution.deferral_never_removes_law
#print axioms Resolution.undecided_edge_incomplete
#print axioms Resolution.delegation_never_widens
#print axioms Resolution.delegation_unknown_incomplete
#print axioms Resolution.Verdict.combAll_perm
