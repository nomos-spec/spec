/-
  Carried Authority, Part II: a mechanized proof of Proposition 1 (omission safety),
  for the gate of NOMOS-SPEC-008 0.5.0 §6.2, and a mechanized counterexample for the
  0.4.0 gate (no clause (ii)).

  Self-contained Lean 4 (core only, no Mathlib). Check with:  lean CarriedAuthority.lean

  Model (paper §3.3, spec §6.2):
  * truth values are Kleene's: f, u (undecided), t;
  * an atom is a comparison over a list of inputs (undecided if any input is absent or the
    values are outside its domain) or `exists x` (decided by absence only for inputs whose
    absence is authoritative: the action's own parameters and the relying party's state);
  * the deciding decision is the condition-true decision of highest rank, where rank is
    (priority, tie rank of the outcome's kind, earlier position);
  * "outranks" (used by the gate) compares priority, then tie rank of the outcome's kind;
    it does NOT use position, exactly as the specification states;
  * gate: an allow or escalate result is held open (INCOMPLETE) if some block/escalate
    decision is undecided and (i) outranks the decider, or (ii) has the decider's priority,
    escalates, while the decider escalates, and names a different escalation.
-/

namespace CarriedAuthority

/-! ## Kleene's strong three-valued logic -/

inductive K3 | f | u | t
  deriving DecidableEq, Repr

namespace K3
def and : K3 → K3 → K3
  | f, _ => f
  | _, f => f
  | t, t => t
  | _, _ => u
def or : K3 → K3 → K3
  | t, _ => t
  | _, t => t
  | f, f => f
  | _, _ => u
def not : K3 → K3
  | f => t
  | u => u
  | t => f
def ofBool : Bool → K3
  | true => t
  | false => f

/-- `Ref a a'`: `a'` refines `a` (an undecided value may become decided; a decided one stays). -/
def Ref (a a' : K3) : Prop := a = u ∨ a' = a

theorem and_ref {a a' b b' : K3} (ha : Ref a a') (hb : Ref b b') : Ref (and a b) (and a' b') := by
  unfold Ref at *
  cases a <;> cases b <;> cases a' <;> cases b' <;> simp_all [and]

theorem or_ref {a a' b b' : K3} (ha : Ref a a') (hb : Ref b b') : Ref (or a b) (or a' b') := by
  unfold Ref at *
  cases a <;> cases b <;> cases a' <;> cases b' <;> simp_all [or]

theorem not_ref {a a' : K3} (ha : Ref a a') : Ref (not a) (not a') := by
  unfold Ref at *
  cases a <;> cases a' <;> simp_all [not]
end K3

open K3

/-! ## Facts, atoms, conditions -/

variable {I V E : Type}

/-- A fact assignment: a partial map from inputs to values. -/
abbrev Facts (I V : Type) := I → Option V

/-- `F'` extends `F` on carried inputs only: every present fact stays, with its value, and
    the inputs whose absence is authoritative (`auth`) are unchanged. -/
structure Ext (auth : I → Bool) (F F' : Facts I V) : Prop where
  keep : ∀ x v, F x = some v → F' x = some v
  fixed : ∀ x, auth x = true → F' x = F x

inductive Atom (I V : Type) where
  /-- a primitive over the listed inputs; `p` returns `none` outside its domain -/
  | cmp (xs : List I) (p : List V → Option Bool)
  /-- `exists x` -/
  | ex (x : I)

inductive Cond (I V : Type) where
  | atom (a : Atom I V)
  | and (c d : Cond I V)
  | or (c d : Cond I V)
  | not (c : Cond I V)

/-- all listed inputs, if every one is present -/
def getAll (F : Facts I V) : List I → Option (List V)
  | [] => some []
  | x :: xs =>
    match F x, getAll F xs with
    | some v, some vs => some (v :: vs)
    | _, _ => none

def evalAtom (auth : I → Bool) (F : Facts I V) : Atom I V → K3
  | .cmp xs p =>
    match getAll F xs with
    | none => u
    | some vs =>
      match p vs with
      | none => u
      | some b => ofBool b
  | .ex x =>
    match F x with
    | some _ => t
    | none => if auth x then f else u

def evalCond (auth : I → Bool) (F : Facts I V) : Cond I V → K3
  | .atom a => evalAtom auth F a
  | .and c d => K3.and (evalCond auth F c) (evalCond auth F d)
  | .or c d => K3.or (evalCond auth F c) (evalCond auth F d)
  | .not c => K3.not (evalCond auth F c)

theorem getAll_ext {auth : I → Bool} {F F' : Facts I V} (h : Ext auth F F') :
    ∀ (xs : List I) (vs : List V), getAll F xs = some vs → getAll F' xs = some vs
  | [], vs, hv => by simpa [getAll] using hv
  | x :: xs, vs, hv => by
    unfold getAll at hv ⊢
    cases hx : F x with
    | none => simp [hx] at hv
    | some v =>
      cases hxs : getAll F xs with
      | none => simp [hx, hxs] at hv
      | some ws =>
        simp [hx, hxs] at hv
        rw [h.keep x v hx, getAll_ext h xs ws hxs]
        simp [hv]

/-- Lemma 1 (atoms are monotone). -/
theorem atom_ref {auth : I → Bool} {F F' : Facts I V} (h : Ext auth F F') (a : Atom I V) :
    Ref (evalAtom auth F a) (evalAtom auth F' a) := by
  unfold Ref
  cases a with
  | cmp xs p =>
    simp only [evalAtom]
    cases hg : getAll F xs with
    | none => left; rfl
    | some vs =>
      rw [getAll_ext h xs vs hg]
      right; rfl
  | ex x =>
    simp only [evalAtom]
    cases hx : F x with
    | some v => right; rw [h.keep x v hx]
    | none =>
      cases ha : auth x with
      | false => left; rfl
      | true => right; rw [h.fixed x ha, hx]

/-- Lemma 2 (conditions are monotone under Kleene's connectives). -/
theorem cond_ref {auth : I → Bool} {F F' : Facts I V} (h : Ext auth F F') :
    ∀ c : Cond I V, Ref (evalCond auth F c) (evalCond auth F' c)
  | .atom a => atom_ref h a
  | .and c d => K3.and_ref (cond_ref h c) (cond_ref h d)
  | .or c d => K3.or_ref (cond_ref h c) (cond_ref h d)
  | .not c => K3.not_ref (cond_ref h c)

/-! ## Authorities, resolution and the gate -/

inductive Out (E : Type) where
  | allow
  | block
  | esc (e : E)

inductive Kind | allow | block | esc
  deriving DecidableEq

def Out.kind : Out E → Kind
  | .allow => .allow
  | .block => .block
  | .esc _ => .esc

theorem kind_esc {o : Out E} (h : o.kind = .esc) : ∃ e, o = .esc e := by
  cases o with
  | allow => cases h
  | block => cases h
  | esc e => exact ⟨e, rfl⟩

theorem kind_allow {o : Out E} (h : o.kind = .allow) : o = .allow := by
  cases o with
  | allow => rfl
  | block => cases h
  | esc e => cases h

/-- a result that could commit: anything but a block -/
def CanCommit (o : Out E) : Prop := o.kind ≠ .block

structure Dec (I V E : Type) where
  cond : Cond I V
  out : Out E
  prio : Nat

structure Authority (I V E : Type) where
  n : Nat
  ds : Fin n → Dec I V E
  /-- tie rank of an outcome kind under the artifact's `tie_breaker` -/
  tr : Kind → Nat
  /-- the tie order is strict on kinds (true of every SPEC-008 tie order) -/
  tr_inj : ∀ a b, tr a = tr b → a = b
  dflt : Out E
  /-- inputs whose absence is authoritative (sources `action`, `relying_party`) -/
  auth : I → Bool

namespace Authority
variable (A : Authority I V E)

def prio (i : Fin A.n) : Nat := (A.ds i).prio
def trk (i : Fin A.n) : Nat := A.tr (A.ds i).out.kind
def val (F : Facts I V) (i : Fin A.n) : K3 := evalCond A.auth F (A.ds i).cond

/-- rank order used to pick the decider: priority, tie rank, earlier position. -/
def RankGt (i j : Fin A.n) : Prop :=
  A.prio i > A.prio j ∨ (A.prio i = A.prio j ∧
    (A.trk i > A.trk j ∨ (A.trk i = A.trk j ∧ i.val < j.val)))

/-- "outranks", as SPEC-008 §6.2 defines it: priority, then tie rank. No position. -/
def Outranks (i j : Fin A.n) : Prop :=
  A.prio i > A.prio j ∨ (A.prio i = A.prio j ∧ A.trk i > A.trk j)

def OutranksOpt (X : Fin A.n) : Option (Fin A.n) → Prop
  | none => True
  | some d => A.Outranks X d

/-- `D` is the deciding decision on `F` (`none`: no condition is true, default applies). -/
def IsDecider (F : Facts I V) : Option (Fin A.n) → Prop
  | none => ∀ j, A.val F j ≠ t
  | some d => A.val F d = t ∧ ∀ j, A.val F j = t → j ≠ d → A.RankGt d j

def outcome : Option (Fin A.n) → Out E
  | none => A.dflt
  | some d => (A.ds d).out

/-- gate clause (ii): equal priority, both escalate, different escalations -/
def Clause2 (X : Fin A.n) : Option (Fin A.n) → Prop
  | none => False
  | some d => ∃ e e', (A.ds d).out = .esc e ∧ (A.ds X).out = .esc e' ∧ e' ≠ e ∧ A.prio X = A.prio d

/-- SPEC-008 0.5.0 §6.2: the result is held open (INCOMPLETE). -/
def GateFires (F : Facts I V) (D : Option (Fin A.n)) : Prop :=
  ∃ X, A.val F X = u ∧ (A.ds X).out.kind ≠ .allow ∧ (A.OutranksOpt X D ∨ A.Clause2 X D)

/-- SPEC-008 0.4.0 §6.2: clause (i) only. -/
def GateFires040 (F : Facts I V) (D : Option (Fin A.n)) : Prop :=
  ∃ X, A.val F X = u ∧ (A.ds X).out.kind ≠ .allow ∧ A.OutranksOpt X D

/-! ### order facts -/

theorem outranks_rankGt {i j : Fin A.n} (h : A.Outranks i j) : A.RankGt i j := by
  unfold Outranks at h; unfold RankGt
  rcases h with h | ⟨h1, h2⟩
  · exact Or.inl h
  · exact Or.inr ⟨h1, Or.inl h2⟩

theorem rankGt_asymm {i j : Fin A.n} (h : A.RankGt i j) : ¬ A.RankGt j i := by
  unfold RankGt at *; omega

theorem rankGt_irrefl (i : Fin A.n) : ¬ A.RankGt i i := by
  unfold RankGt; omega

theorem outranks_trans {i j k : Fin A.n} (h1 : A.Outranks i j) (h2 : A.Outranks j k) :
    A.Outranks i k := by
  unfold Outranks at *; omega

/-! ### refinement on decisions -/

variable {A}

theorem val_ref {F F' : Facts I V} (h : Ext A.auth F F') (i : Fin A.n) :
    Ref (A.val F i) (A.val F' i) := cond_ref h _

theorem val_t {F F' : Facts I V} (h : Ext A.auth F F') {i : Fin A.n} (hi : A.val F i = t) :
    A.val F' i = t := by
  rcases val_ref h i with h1 | h1
  · rw [hi] at h1; cases h1
  · rw [h1, hi]

theorem val_f {F F' : Facts I V} (h : Ext A.auth F F') {i : Fin A.n} (hi : A.val F i = f) :
    A.val F' i = f := by
  rcases val_ref h i with h1 | h1
  · rw [hi] at h1; cases h1
  · rw [h1, hi]

theorem val_u_back {F F' : Facts I V} (h : Ext A.auth F F') {i : Fin A.n} (hi : A.val F' i = u) :
    A.val F i = u := by
  rcases val_ref h i with h1 | h1
  · exact h1
  · rw [← h1, hi]

/-- Step 1: a block/escalate decision that outranks the decider is false, under a closed gate. -/
theorem stopper_false {F : Facts I V} {D : Option (Fin A.n)} (hD : A.IsDecider F D)
    (hg : ¬ A.GateFires F D) {X : Fin A.n} (hk : (A.ds X).out.kind ≠ .allow)
    (ho : A.OutranksOpt X D) : A.val F X = f := by
  cases hv : A.val F X with
  | f => rfl
  | u => exact absurd ⟨X, hv, hk, Or.inl ho⟩ hg
  | t =>
    cases D with
    | none => exact absurd hv (hD X)
    | some d =>
      have ho' : A.Outranks X d := ho
      have hne : X ≠ d := by
        intro hx; subst hx; exact A.rankGt_irrefl X (A.outranks_rankGt ho')
      exact absurd (A.outranks_rankGt ho') (A.rankGt_asymm (hD.2 X hv hne))

/-! ## Proposition 1 (omission safety), for the 0.5.0 gate -/

/-- If a result on the presented facts `F` could commit (allow, or escalate e) with the gate
    closed, then on every extension `F'` of the carried facts:
    * an allow stays an allow;
    * an escalation stays the same escalation, or becomes an allow;
    * the gate stays closed (so the result is neither DENIED nor INCOMPLETE). -/
theorem omission_safety {F F' : Facts I V} (hext : Ext A.auth F F')
    {D D' : Option (Fin A.n)} (hD : A.IsDecider F D) (hD' : A.IsDecider F' D')
    (hc : CanCommit (A.outcome D)) (hg : ¬ A.GateFires F D) :
    (A.outcome D = .allow → A.outcome D' = .allow) ∧
    (∀ e, A.outcome D = .esc e → A.outcome D' = .esc e ∨ A.outcome D' = .allow) ∧
    ¬ A.GateFires F' D' := by
  cases D with
  | none =>
    cases D' with
    | none =>
      refine ⟨fun h => h, fun e h => Or.inl h, ?_⟩
      rintro ⟨X, hu, hk, hcl⟩
      rcases hcl with ho | hc2
      · exact hg ⟨X, val_u_back hext hu, hk, Or.inl ho⟩
      · exact hc2.elim
    | some d' =>
      have hd't : A.val F' d' = t := hD'.1
      -- d' must be an allow: a stopper outranks "none", so it is false on F and on F'
      have hka : (A.ds d').out.kind = .allow := by
        cases hk : (A.ds d').out.kind with
        | allow => rfl
        | block | esc =>
          have := val_f hext (stopper_false hD hg (X := d') (by rw [hk]; decide) trivial)
          rw [hd't] at this; cases this
      have hoa : A.outcome (some d') = .allow := by
        show (A.ds d').out = .allow
        cases h : (A.ds d').out with
        | allow => rfl
        | block => rw [h] at hka; cases hka
        | esc e => rw [h] at hka; cases hka
      refine ⟨fun _ => hoa, fun _ _ => Or.inr hoa, ?_⟩
      rintro ⟨X, hu, hk, hcl⟩
      rcases hcl with _ | ⟨e, e', h1, _, _, _⟩
      · exact hg ⟨X, val_u_back hext hu, hk, Or.inl trivial⟩
      · rw [h1] at hka; cases hka
  | some d =>
    have hdt : A.val F d = t := hD.1
    have hdt' : A.val F' d = t := val_t hext hdt
    cases D' with
    | none => exact absurd hdt' (hD' d)
    | some d' =>
      by_cases hsame : d' = d
      · subst hsame
        refine ⟨fun h => h, fun e h => Or.inl h, ?_⟩
        rintro ⟨X, hu, hk, hcl⟩
        exact hg ⟨X, val_u_back hext hu, hk, hcl⟩
      · have hrk : A.RankGt d' d := hD'.2 d hdt' (fun h => hsame h.symm)
        -- the new decider is an allow, or carries d's outcome at d's priority
        have hclaim : (A.ds d').out.kind = .allow ∨
            ((A.ds d').out = (A.ds d).out ∧ A.prio d' = A.prio d ∧ A.trk d' = A.trk d) := by
          cases hk' : (A.ds d').out.kind with
          | allow => exact Or.inl rfl
          | block | esc =>
            have hk'' : (A.ds d').out.kind ≠ .allow := by rw [hk']; decide
            right
            cases hv : A.val F d' with
            | t => exact absurd (hD.2 d' hv hsame) (A.rankGt_asymm hrk)
            | f => have := val_f hext hv; rw [hD'.1] at this; cases this
            | u =>
              have hnot : ¬ A.Outranks d' d := fun ho => hg ⟨d', hv, hk'', Or.inl ho⟩
              have hp : A.prio d' = A.prio d := by
                unfold RankGt at hrk; unfold Outranks at hnot; omega
              have ht : A.trk d' = A.trk d := by
                unfold RankGt at hrk; unfold Outranks at hnot; omega
              have hkind : (A.ds d').out.kind = (A.ds d).out.kind := A.tr_inj _ _ ht
              refine ⟨?_, hp, ht⟩
              -- same kind; d can commit and d' is not an allow, so both escalate
              have hdk : (A.ds d).out.kind = .esc := by
                cases h : (A.ds d).out.kind with
                | allow => rw [h] at hkind; exact absurd hkind hk''
                | block => exact absurd h hc
                | esc => rfl
              obtain ⟨e, hdo⟩ := kind_esc hdk
              obtain ⟨e', hd'o⟩ := kind_esc (hkind.trans hdk)
              by_cases hee : e' = e
              · rw [hd'o, hdo, hee]
              · exact absurd ⟨d', hv, hk'', Or.inr ⟨e, e', hdo, hd'o, hee, hp⟩⟩ hg
        have hout : A.outcome (some d') = .allow ∨ A.outcome (some d') = A.outcome (some d) := by
          rcases hclaim with hka | ⟨ho, _, _⟩
          · left
            show (A.ds d').out = .allow
            cases h : (A.ds d').out with
            | allow => rfl
            | block => rw [h] at hka; cases hka
            | esc e => rw [h] at hka; cases hka
          · exact Or.inr ho
        refine ⟨?_, ?_, ?_⟩
        · intro h; rcases hout with h1 | h1
          · exact h1
          · rw [h1, h]
        · intro e h; rcases hout with h1 | h1
          · exact Or.inr h1
          · exact Or.inl (h1.trans h)
        · rintro ⟨X, hu, hk, hcl⟩
          have huF := val_u_back hext hu
          rcases hcl with ho | ⟨e1, e2, h1, h2, h3, h4⟩
          · -- clause (i) against d' transfers to d
            have ho' : A.Outranks X d' := ho
            have hXd : A.Outranks X d := by
              rcases hclaim with _ | ⟨_, hp, ht⟩
              · unfold RankGt at hrk; unfold Outranks at ho' ⊢
                rcases hrk with hrk | ⟨hrk1, hrk2 | ⟨hrk2, _⟩⟩
                · omega
                · omega
                · -- equal priority and tie rank with d: outranking d' is outranking d
                  omega
              · unfold Outranks at ho' ⊢; omega
            exact hg ⟨X, huF, hk, Or.inl hXd⟩
          · -- clause (ii) against d' transfers to d
            rcases hclaim with hka | ⟨ho, hp, _⟩
            · rw [h1] at hka; cases hka
            · rw [ho] at h1
              exact hg ⟨X, huF, hk, Or.inr ⟨e1, e2, h1, h2, h3, h4.trans hp⟩⟩

/-- Corollary: under the 0.5.0 gate, completing the facts never yields DENIED. -/
theorem never_denied {F F' : Facts I V} (hext : Ext A.auth F F')
    {D D' : Option (Fin A.n)} (hD : A.IsDecider F D) (hD' : A.IsDecider F' D')
    (hc : CanCommit (A.outcome D)) (hg : ¬ A.GateFires F D) :
    CanCommit (A.outcome D') := by
  obtain ⟨h1, h2, _⟩ := omission_safety hext hD hD' hc hg
  unfold CanCommit at *
  cases ho : A.outcome D with
  | allow => rw [h1 ho]; intro h; cases h
  | block => rw [ho] at hc; exact absurd rfl hc
  | esc e =>
    rcases h2 e ho with h | h <;> rw [h] <;> (intro h'; cases h')

end Authority

/-! ## The 0.4.0 gate is not omission-safe (vector 30, mechanized) -/

namespace Counterexample
open Authority

/-- One witnessed input (`days_since_delinquency`); escalations: `true` = dual senior
    approval (R16), `false` = one reviewer (R10). Both at priority 70, R16 listed first. -/
def R16 : Dec Unit Nat Bool :=
  { cond := .atom (.cmp [()] (fun vs => match vs with | [v] => some (decide (v < 365)) | _ => none)),
    out := .esc true, prio := 70 }
def R10 : Dec Unit Nat Bool :=
  { cond := .atom (.cmp [] (fun _ => some true)),  -- amount > 10,000: true for this act
    out := .esc false, prio := 70 }

def A : Authority Unit Nat Bool where
  n := 2
  ds := fun i => if i.val = 0 then R16 else R10
  tr := fun k => match k with | .allow => 0 | .esc => 1 | .block => 2
  tr_inj := by intro a b h; cases a <;> cases b <;> simp_all
  dflt := .block
  auth := fun _ => false

/-- the Act withholds the delinquency statement -/
def F : Facts Unit Nat := fun _ => none
/-- the world: a delinquency 100 days ago -/
def F' : Facts Unit Nat := fun _ => some 100

def i0 : Fin 2 := ⟨0, by decide⟩
def i1 : Fin 2 := ⟨1, by decide⟩

theorem val_F_0 : A.val F i0 = u := rfl
theorem val_F_1 : A.val F i1 = t := rfl
theorem val_F'_0 : A.val F' i0 = t := rfl
theorem val_F'_1 : A.val F' i1 = t := rfl

theorem fin2 (j : Fin 2) : j = i0 ∨ j = i1 := by
  rcases j with ⟨j, hj⟩
  have : j = 0 ∨ j = 1 := by omega
  rcases this with rfl | rfl
  · exact Or.inl rfl
  · exact Or.inr rfl

theorem ext : Ext A.auth F F' :=
  ⟨fun _ v h => by simp [F] at h, fun _ h => by simp [A] at h⟩

/-- On the presented facts, R10 decides: escalate to one reviewer. -/
theorem decider_F : A.IsDecider F (some i1) := by
  refine ⟨rfl, ?_⟩
  intro j hj hne
  rcases fin2 j with rfl | rfl
  · rw [val_F_0] at hj; cases hj
  · exact absurd rfl hne

/-- On the true facts, R16 decides: escalate to two senior approvers. -/
theorem decider_F' : A.IsDecider F' (some i0) := by
  refine ⟨rfl, ?_⟩
  intro j _ hne
  rcases fin2 j with rfl | rfl
  · exact absurd rfl hne
  · unfold RankGt prio trk; simp [A, i0, i1, R16, R10, Out.kind]

/-- The 0.4.0 gate does not fire: R16 is undecided but does not "outrank" R10. -/
theorem gate040_closed : ¬ A.GateFires040 F (some i1) := by
  rintro ⟨X, hu, _, ho⟩
  rcases fin2 X with rfl | rfl
  · have : A.Outranks i0 i1 := ho
    unfold Outranks prio trk at this; simp [A, i0, i1, R16, R10, Out.kind] at this
  · rw [val_F_1] at hu; cases hu

/-- The 0.5.0 gate fires: clause (ii). -/
theorem gate050_fires : A.GateFires F (some i1) :=
  ⟨i0, rfl, by simp [A, i0, R16, Out.kind], Or.inr ⟨false, true, rfl, rfl, by decide, rfl⟩⟩

/-- Under 0.4.0 the carrier, by withholding one fact, obtains escalation `false` (one
    reviewer) where the true facts require escalation `true` (two senior approvers). -/
theorem gate040_unsafe :
    Ext A.auth F F' ∧ A.IsDecider F (some i1) ∧ A.IsDecider F' (some i0) ∧
    ¬ A.GateFires040 F (some i1) ∧
    A.outcome (some i1) = .esc false ∧ A.outcome (some i0) = .esc true :=
  ⟨ext, decider_F, decider_F', gate040_closed, rfl, rfl⟩

end Counterexample

end CarriedAuthority
