/-
  The parser inverts the printer (OracleExpr.lean): for every well-formed condition `e`,
  `parse (print e) = some e`. So a printed condition has exactly the one reading it was printed
  from, whatever its nesting, and the parser's fuel always suffices.

  Well-formed: comparison operators are == != > >= < <=, relations are in contains between, and
  no field is named after a keyword (`true`, `false`, `always`, `and`, `or`, `not`, `exists`,
  `matches`, `in`, `contains`, `between`). This is a statement about the parser over tokens; the
  tokenizer, which turns text into tokens, is not covered.
-/
import OracleExpr

namespace OracleExpr

def keywords : List String :=
  ["true", "false", "always", "and", "or", "not", "exists", "matches", "in", "contains", "between"]

def WFOpd : Opd → Prop
  | .field p => p ∉ keywords
  | _ => True

def WF : Expr → Prop
  | .or a b => WF a ∧ WF b
  | .and a b => WF a ∧ WF b
  | .not a => WF a
  | .cmp o l r => o ∈ cmpOps ∧ WFOpd l ∧ WFOpd r
  | .rel o l r => o ∈ relOps ∧ WFOpd l ∧ WFOpd r
  | .ex o => WFOpd o
  | .matches o p => WFOpd o ∧ WFOpd p
  | .bare o => WFOpd o

def size : Expr → Nat
  | .or a b => size a + size b + 1
  | .and a b => size a + size b + 1
  | .not a => size a + 1
  | _ => 1

/-- what may follow a condition in printed text: nothing, or a closing parenthesis -/
def Stop (r : List Tok) : Prop := r = [] ∨ ∃ r', r = .op ")" :: r'

theorem operand_print {o : Opd} (h : WFOpd o) (r : List Tok) :
    operand (printOpd o :: r) = some (o, r) := by
  cases o with
  | num s => rfl
  | str s => rfl
  | bool b => cases b <;> rfl
  | field p =>
    simp only [WFOpd, keywords, List.mem_cons, List.not_mem_nil, or_false, not_or] at h
    obtain ⟨h1, h2, h3, -⟩ := h
    simp [printOpd, operand, h1, h2, h3]

theorem orTail_stop {k : Nat} {a : Expr} {r : List Tok} (h : Stop r) :
    pOrTail (k + 1) a r = some (a, r) := by
  rcases h with rfl | ⟨r', rfl⟩ <;> simp [pOrTail]

theorem andTail_stop {k : Nat} {a : Expr} {r : List Tok} (h : Stop r) :
    pAndTail (k + 1) a r = some (a, r) := by
  rcases h with rfl | ⟨r', rfl⟩ <;> simp [pAndTail]

theorem andTail_or {k : Nat} {a : Expr} {r : List Tok} :
    pAndTail (k + 1) a (.id "or" :: r) = some (a, .id "or" :: r) := by
  simp [pAndTail]

theorem size_pos (e : Expr) : 1 ≤ size e := by
  cases e <;> simp [size] <;> omega

theorem printOpd_ne_not {o : Opd} (h : WFOpd o) : printOpd o ≠ .id "not" := by
  cases o with
  | num s => simp [printOpd]
  | str s => simp [printOpd]
  | bool b => cases b <;> simp [printOpd]
  | field p =>
    simp only [WFOpd, keywords, List.mem_cons, List.not_mem_nil, or_false, not_or] at h
    simp [printOpd]; exact h.2.2.2.2.2.1

theorem unary_prim {k : Nat} {t : Tok} {r : List Tok} (h : t ≠ .id "not") :
    pUnary (k + 1) (t :: r) = pPrimary k (t :: r) := by
  cases t with
  | id s =>
    have : s ≠ "not" := fun e => h (by rw [e])
    simp [pUnary, this]
  | _ => simp [pUnary]

/-- what the last branch of `pPrimary` does after reading an operand -/
def atomRest (l : Opd) (r : List Tok) : Option (Expr × List Tok) :=
  match r with
  | .op o :: r' =>
    if o ∈ cmpOps then (operand r').bind fun (rt, r'') => some (.cmp o l rt, r'')
    else some (.bare l, r)
  | .id o :: r' =>
    if o ∈ relOps then (operand r').bind fun (rt, r'') => some (.rel o l rt, r'')
    else some (.bare l, r)
  | _ => some (.bare l, r)

theorem primary_opd {k : Nat} {l : Opd} (h : WFOpd l) (r : List Tok) :
    pPrimary (k + 1) (printOpd l :: r) = atomRest l r := by
  have hop := operand_print h r
  have hl : ∀ s, printOpd l = .id s → s ≠ "exists" ∧ s ≠ "matches" := by
    intro s hs
    cases l with
    | num _ => simp [printOpd] at hs
    | str _ => simp [printOpd] at hs
    | bool b => cases b <;> simp [printOpd] at hs <;> subst hs <;> decide
    | field p =>
      simp only [printOpd, Tok.id.injEq] at hs; subst hs
      simp only [WFOpd, keywords, List.mem_cons, List.not_mem_nil, or_false, not_or] at h
      exact ⟨h.2.2.2.2.2.2.1, h.2.2.2.2.2.2.2.1⟩
  have hnp : printOpd l ≠ .op "(" := by cases l <;> (try cases ‹Bool›) <;> simp [printOpd]
  unfold pPrimary
  split
  · simp_all
  · rename_i heq; simp only [List.cons.injEq] at heq; exact absurd heq.1 hnp
  · rename_i heq; simp only [List.cons.injEq] at heq; exact absurd heq.1.symm (by
      intro e; exact (hl "exists" e.symm).1 rfl)
  · rename_i heq; simp only [List.cons.injEq] at heq; exact absurd heq.1.symm (by
      intro e; exact (hl "matches" e.symm).2 rfl)
  · rw [hop]; unfold atomRest
    rcases r with _ | ⟨t, r'⟩
    · rfl
    · cases t <;> rfl

theorem pExpr_succ (n : Nat) (ts : List Tok) :
    pExpr (n + 1) ts = (pAnd n ts).bind (fun p => pOrTail n p.1 p.2) := by
  rw [pExpr]; rfl

theorem pAnd_succ (n : Nat) (ts : List Tok) :
    pAnd (n + 1) ts = (pUnary n ts).bind (fun p => pAndTail n p.1 p.2) := by
  rw [pAnd]; rfl

theorem pPrimary_paren (n : Nat) (r : List Tok) :
    pPrimary (n + 1) (.op "(" :: r) =
      (pExpr n r).bind (fun p => match p.2 with
        | .op ")" :: r'' => some (p.1, r'')
        | _ => none) := by
  rw [pPrimary]; rfl

theorem pOrTail_or (n : Nat) (a : Expr) (r : List Tok) :
    pOrTail (n + 1) a (.id "or" :: r) = (pAnd n r).bind (fun p => pOrTail n (.or a p.1) p.2) := by
  rw [pOrTail]; rfl

theorem pAndTail_and (n : Nat) (a : Expr) (r : List Tok) :
    pAndTail (n + 1) a (.id "and" :: r) = (pUnary n r).bind (fun p => pAndTail n (.and a p.1) p.2) := by
  rw [pAndTail]; rfl

theorem pUnary_not (n : Nat) (r : List Tok) :
    pUnary (n + 1) (.id "not" :: r) = (pUnary n r).bind (fun p => some (.not p.1, p.2)) := by
  rw [pUnary]; rfl

/-- an atom read by `pPrimary`, followed by what may follow a condition -/
theorem primary_atom {k : Nat} {rest : List Tok} (hs : Stop rest) :
    ∀ e, WF e → (∀ a b, e ≠ .or a b) → (∀ a b, e ≠ .and a b) → (∀ a, e ≠ .not a) →
    pPrimary (k + 1) (print e ++ rest) = some (e, rest) ∧ ∃ t r, print e ++ rest = t :: r ∧ t ≠ .id "not"
  | .or a b, _, h, _, _ => absurd rfl (h a b)
  | .and a b, _, _, h, _ => absurd rfl (h a b)
  | .not a, _, _, _, h => absurd rfl (h a)
  | .cmp o l r, ⟨ho, hl, hr⟩, _, _, _ => by
    refine ⟨?_, _, _, rfl, printOpd_ne_not hl⟩
    simp only [print, List.cons_append, List.nil_append]
    rw [primary_opd hl]; simp [atomRest, ho, operand_print hr]
  | .rel o l r, ⟨ho, hl, hr⟩, _, _, _ => by
    refine ⟨?_, _, _, rfl, printOpd_ne_not hl⟩
    simp only [print, List.cons_append, List.nil_append]
    rw [primary_opd hl]
    have : o ∉ cmpOps := by
      simp only [relOps, List.mem_cons, List.not_mem_nil, or_false] at ho
      rcases ho with rfl | rfl | rfl <;> decide
    simp [atomRest, ho, operand_print hr]
  | .bare o, hw, _, _, _ => by
    refine ⟨?_, _, _, rfl, printOpd_ne_not hw⟩
    simp only [print, List.cons_append, List.nil_append]
    rw [primary_opd hw]
    rcases hs with rfl | ⟨r', rfl⟩
    · rfl
    · simp [atomRest, cmpOps]
  | .ex o, hw, _, _, _ => by
    refine ⟨?_, _, _, rfl, by simp⟩
    simp only [print, List.cons_append, List.nil_append]
    rw [pPrimary]; simp [operand_print hw]
  | .matches o q, ⟨ho, hq⟩, _, _, _ => by
    refine ⟨?_, _, _, rfl, by simp⟩
    simp only [print, List.cons_append, List.nil_append]
    rw [pPrimary]; simp [operand_print ho, operand_print hq]

theorem paren_ne_not : Tok.op "(" ≠ Tok.id "not" := by decide

/-- The parser reads a printed condition back, followed by anything that may follow one,
    given fuel of five per node. -/
theorem pExpr_print : ∀ e : Expr, WF e → ∀ rest : List Tok, Stop rest → ∀ n, 5 * size e ≤ n →
    pExpr n (print e ++ rest) = some (e, rest) := by
  intro e
  induction e with
  | or a b iha ihb =>
    intro ⟨wa, wb⟩ rest hs n hn
    simp only [size] at hn
    have := size_pos a; have := size_pos b
    obtain ⟨k, rfl⟩ : ∃ k, n = k + 5 := ⟨n - 5, by omega⟩
    have ha := iha wa (.op ")" :: .id "or" :: .op "(" :: (print b ++ .op ")" :: rest)) (Or.inr ⟨_, rfl⟩) (k + 1) (by omega)
    have hb := ihb wb (.op ")" :: rest) (Or.inr ⟨_, rfl⟩) k (by omega)
    simp only [print, List.append_assoc, List.cons_append, List.nil_append]
    rw [pExpr_succ, pAnd_succ, unary_prim paren_ne_not, pPrimary_paren, ha]
    simp only [Option.bind, andTail_or]
    rw [pOrTail_or, pAnd_succ, unary_prim paren_ne_not, pPrimary_paren, hb]
    simp only [Option.bind, andTail_stop hs, orTail_stop hs]
  | and a b iha ihb =>
    intro ⟨wa, wb⟩ rest hs n hn
    simp only [size] at hn
    have := size_pos a; have := size_pos b
    obtain ⟨k, rfl⟩ : ∃ k, n = k + 5 := ⟨n - 5, by omega⟩
    have ha := iha wa (.op ")" :: .id "and" :: .op "(" :: (print b ++ .op ")" :: rest)) (Or.inr ⟨_, rfl⟩) (k + 1) (by omega)
    have hb := ihb wb (.op ")" :: rest) (Or.inr ⟨_, rfl⟩) k (by omega)
    simp only [print, List.append_assoc, List.cons_append, List.nil_append]
    rw [pExpr_succ, pAnd_succ, unary_prim paren_ne_not, pPrimary_paren, ha]
    simp only [Option.bind]
    rw [pAndTail_and, unary_prim paren_ne_not, pPrimary_paren, hb]
    simp only [Option.bind, andTail_stop hs, orTail_stop hs]
  | not a iha =>
    intro wa rest hs n hn
    simp only [size] at hn
    have := size_pos a
    obtain ⟨k, rfl⟩ : ∃ k, n = k + 5 := ⟨n - 5, by omega⟩
    have ha := iha wa (.op ")" :: rest) (Or.inr ⟨_, rfl⟩) k (by omega)
    simp only [print, List.append_assoc, List.cons_append, List.nil_append]
    rw [pExpr_succ, pAnd_succ, pUnary_not, unary_prim paren_ne_not, pPrimary_paren, ha]
    simp only [Option.bind, andTail_stop hs, orTail_stop hs]
  | cmp o l r | rel o l r | ex o | «matches» o q | bare o =>
    intro hw rest hs n hn
    simp only [size] at hn
    obtain ⟨k, rfl⟩ : ∃ k, n = k + 5 := ⟨n - 5, by omega⟩
    obtain ⟨hp, t, r', heq, ht⟩ := primary_atom (k := k + 1) hs _ hw
      (by intros; simp) (by intros; simp) (by intros; simp)
    rw [pExpr_succ, pAnd_succ, heq, unary_prim ht, ← heq, hp]
    simp only [Option.bind, andTail_stop hs, orTail_stop hs]

theorem size_le_length (e : Expr) : size e ≤ (print e).length := by
  induction e with
  | or a b iha ihb => simp only [size, print, List.length_append, List.length_cons, List.length_nil]; omega
  | and a b iha ihb => simp only [size, print, List.length_append, List.length_cons, List.length_nil]; omega
  | not a iha => simp only [size, print, List.length_append, List.length_cons, List.length_nil]; omega
  | _ => simp [size, print]

/-- **The parser inverts the printer**: every well-formed condition, printed, is parsed back
    to itself. -/
theorem parse_print (e : Expr) (hw : WF e) : parse (print e) = some e := by
  have h := pExpr_print e hw [] (Or.inl rfl) (8 * (print e).length + 8)
    (by have := size_le_length e; omega)
  simp only [List.append_nil] at h
  simp [parse, h]

end OracleExpr

#print axioms OracleExpr.parse_print
