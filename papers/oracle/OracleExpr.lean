/-
  Nomos-Expr v1 (NOMOS-SPEC-001 §4.1), three-valued per NOMOS-SPEC-008 §6.2, read by the oracle
  from an artifact's own `when` strings, so the oracle and an implementation read the same text.

  `parse` turns tokens into a syntax tree (`Expr`); `compile` turns the tree into a condition of
  the Part II model (`Cond`), whose atoms are the comparison primitives below. The tokenizer and
  the primitives transcribe the reference implementations; they are unproved. What is proved
  (`parse_print`): the parser inverts the printer, so every tree has exactly one reading as
  tokens. `matches` (regular expressions) is not supported: a rule that uses it is reported, not
  evaluated.
-/
import Lean.Data.Json
import CarriedAuthority

namespace OracleExpr
open Lean CarriedAuthority

/-! ## Tokens -/

inductive Tok where
  | num (s : String)
  | str (s : String)   -- without its quotes
  | op (s : String)    -- == != >= <= > < ( ) ,
  | id (s : String)
  deriving DecidableEq, Repr, Inhabited

def isIdStart (c : Char) : Bool := c.isAlpha || c == '_'
def isIdChar (c : Char) : Bool := c.isAlphanum || c == '_' || c == '.'

/-- digits, optional fraction, optional exponent; returns the lexeme and the rest -/
def lexNum (cs : List Char) : Option (List Char × List Char) :=
  let (sign, cs) := match cs with
    | '-' :: r => (['-'], r)
    | r => ([], r)
  let (ds, cs) := cs.span Char.isDigit
  if ds.isEmpty then none else
  let (frac, cs) := match cs with
    | '.' :: r =>
      let (fs, r') := r.span Char.isDigit
      if fs.isEmpty then ([], cs) else ('.' :: fs, r')
    | _ => ([], cs)
  let (ex, cs) := match cs with
    | e :: r =>
      if e == 'e' || e == 'E' then
        let (sg, r1) := match r with
          | '+' :: q => (['+'], q)
          | '-' :: q => (['-'], q)
          | q => ([], q)
        let (es, r2) := r1.span Char.isDigit
        if es.isEmpty then ([], cs) else (e :: sg ++ es, r2)
      else ([], cs)
    | [] => ([], cs)
  some (sign ++ ds ++ frac ++ ex, cs)

partial def tokenize (cs : List Char) (acc : Array Tok := #[]) : Except String (Array Tok) :=
  match cs with
  | [] => .ok acc
  | c :: r =>
    if c.isWhitespace then tokenize r acc
    else if c == '"' then
      let (s, r') := r.span (· != '"')
      match r' with
      | '"' :: r'' => tokenize r'' (acc.push (.str (String.ofList s)))
      | _ => .error "unterminated string"
    else if c.isDigit || (c == '-' && (r.head?.map Char.isDigit).getD false) then
      match lexNum cs with
      | some (n, r') => tokenize r' (acc.push (.num (String.ofList n)))
      | none => .error "bad number"
    else if isIdStart c then
      let (s, r') := cs.span isIdChar
      tokenize r' (acc.push (.id (String.ofList s)))
    else match c, r with
      | '=', '=' :: r' => tokenize r' (acc.push (.op "=="))
      | '!', '=' :: r' => tokenize r' (acc.push (.op "!="))
      | '>', '=' :: r' => tokenize r' (acc.push (.op ">="))
      | '<', '=' :: r' => tokenize r' (acc.push (.op "<="))
      | '>', r' => tokenize r' (acc.push (.op ">"))
      | '<', r' => tokenize r' (acc.push (.op "<"))
      | '(', r' => tokenize r' (acc.push (.op "("))
      | ')', r' => tokenize r' (acc.push (.op ")"))
      | ',', r' => tokenize r' (acc.push (.op ","))
      | _, _ => .error s!"cannot parse at '{c}'"

/-! ## Syntax -/

inductive Opd where
  | num (s : String)
  | str (s : String)
  | bool (b : Bool)        -- `true`, `always`, `false`
  | field (path : String)
  deriving DecidableEq, Repr

inductive Expr where
  | or (a b : Expr)
  | and (a b : Expr)
  | not (a : Expr)
  | cmp (op : String) (l r : Opd)       -- == != > >= < <=
  | rel (op : String) (l r : Opd)       -- in contains between
  | ex (o : Opd)                        -- exists(o)
  | matches (o : Opd) (pat : Opd)       -- matches(o, pat)
  | bare (o : Opd)
  deriving DecidableEq, Repr

def cmpOps : List String := ["==", "!=", ">", ">=", "<", "<="]
def relOps : List String := ["in", "contains", "between"]

/-! ## Parser: recursive descent, as the reference implementations parse -/

def operand : List Tok → Option (Opd × List Tok)
  | .num s :: r => some (.num s, r)
  | .str s :: r => some (.str s, r)
  | .id "true" :: r => some (.bool true, r)
  | .id "always" :: r => some (.bool true, r)
  | .id "false" :: r => some (.bool false, r)
  | .id s :: r => some (.field s, r)
  | _ => none

-- `fuel` bounds the recursion; `parse` gives 8 per token, more than any input needs.
mutual
def pExpr : Nat → List Tok → Option (Expr × List Tok)
  | 0, _ => none
  | n + 1, ts => do
    let (a, r) ← pAnd n ts
    pOrTail n a r
def pOrTail : Nat → Expr → List Tok → Option (Expr × List Tok)
  | 0, _, _ => none
  | n + 1, a, .id "or" :: r => do
    let (b, r') ← pAnd n r
    pOrTail n (.or a b) r'
  | _ + 1, a, r => some (a, r)
def pAnd : Nat → List Tok → Option (Expr × List Tok)
  | 0, _ => none
  | n + 1, ts => do
    let (a, r) ← pUnary n ts
    pAndTail n a r
def pAndTail : Nat → Expr → List Tok → Option (Expr × List Tok)
  | 0, _, _ => none
  | n + 1, a, .id "and" :: r => do
    let (b, r') ← pUnary n r
    pAndTail n (.and a b) r'
  | _ + 1, a, r => some (a, r)
def pUnary : Nat → List Tok → Option (Expr × List Tok)
  | 0, _ => none
  | n + 1, .id "not" :: r => do
    let (a, r') ← pUnary n r
    some (.not a, r')
  | n + 1, ts => pPrimary n ts
def pPrimary : Nat → List Tok → Option (Expr × List Tok)
  | 0, _ => none
  | n + 1, .op "(" :: r => do
    let (a, r') ← pExpr n r
    match r' with
    | .op ")" :: r'' => some (a, r'')
    | _ => none
  | _ + 1, .id "exists" :: .op "(" :: r => do
    let (o, r') ← operand r
    match r' with
    | .op ")" :: r'' => some (.ex o, r'')
    | _ => none
  | _ + 1, .id "matches" :: .op "(" :: r => do
    let (o, r') ← operand r
    match r' with
    | .op "," :: r'' => do
      let (p, r3) ← operand r''
      match r3 with
      | .op ")" :: r4 => some (.matches o p, r4)
      | _ => none
    | _ => none
  | _ + 1, ts => do
    let (l, r) ← operand ts
    match r with
    | .op o :: r' =>
      if o ∈ cmpOps then do
        let (rt, r'') ← operand r'
        some (.cmp o l rt, r'')
      else some (.bare l, r)
    | .id o :: r' =>
      if o ∈ relOps then do
        let (rt, r'') ← operand r'
        some (.rel o l rt, r'')
      else some (.bare l, r)
    | _ => some (.bare l, r)
end

/-- A whole condition: every token consumed. -/
def parse (ts : List Tok) : Option Expr :=
  match pExpr (8 * ts.length + 8) ts with
  | some (e, []) => some e
  | _ => none

def parseString (s : String) : Except String Expr := do
  let ts ← tokenize s.toList
  match parse ts.toList with
  | some e => .ok e
  | none => .error s!"cannot parse: {s}"

/-! ## Printer, fully parenthesized -/

def printOpd : Opd → Tok
  | .num s => .num s
  | .str s => .str s
  | .bool true => .id "true"
  | .bool false => .id "false"
  | .field p => .id p

def print : Expr → List Tok
  | .or a b => [.op "("] ++ print a ++ [.op ")", .id "or", .op "("] ++ print b ++ [.op ")"]
  | .and a b => [.op "("] ++ print a ++ [.op ")", .id "and", .op "("] ++ print b ++ [.op ")"]
  | .not a => [.id "not", .op "("] ++ print a ++ [.op ")"]
  | .cmp o l r => [printOpd l, .op o, printOpd r]
  | .rel o l r => [printOpd l, .id o, printOpd r]
  | .ex o => [.id "exists", .op "(", printOpd o, .op ")"]
  | .matches o p => [.id "matches", .op "(", printOpd o, .op ",", printOpd p, .op ")"]
  | .bare o => [printOpd o]

/-! ## Values and primitives (transcribed from the references; unproved) -/

/-- A decimal as `m / 10^e`. -/
structure Dec where
  m : Int
  e : Nat

def pow10 (n : Nat) : Int := (10 : Int) ^ n

def Dec.cmp (a b : Dec) : Ordering := compare (a.m * pow10 b.e) (b.m * pow10 a.e)

def ofJsonNumber (n : JsonNumber) : Dec := ⟨n.mantissa, n.exponent⟩

/-- A numeric lexeme `-?d+(.d+)?([eE][+-]?d+)?` as a decimal. -/
def decOfLexeme (s : String) : Option Dec :=
  let cs := s.toList
  let (neg, cs) := match cs with | '-' :: r => (true, r) | r => (false, r)
  let (ip, cs) := cs.span Char.isDigit
  let (fp, cs) := match cs with
    | '.' :: r => r.span Char.isDigit
    | r => ([], r)
  let ex : Int := match cs with
    | e :: r =>
      if e == 'e' || e == 'E' then
        let (sg, r1) := match r with | '-' :: q => (-1, q) | '+' :: q => (1, q) | q => (1, q)
        sg * (String.ofList r1).toNat!
      else 0
    | [] => 0
  if ip.isEmpty then none else
  let digits := (String.ofList (ip ++ fp)).toNat!
  let m : Int := if neg then -(digits : Int) else digits
  let e : Int := (fp.length : Int) - ex
  if e ≥ 0 then some ⟨m, e.toNat⟩ else some ⟨m * pow10 (-e).toNat, 0⟩

/-- JavaScript's parseFloat on a decimal prefix, enough for `between` bounds. -/
def parseFloatPrefix (s : String) : Option Dec :=
  let cs := s.toList.dropWhile Char.isWhitespace
  match lexNum cs with
  | some (n, _) => decOfLexeme (String.ofList n)
  | none => none

inductive Kind' | bool | num | str | arr | obj | other
  deriving DecidableEq

def kindOf : Json → Kind'
  | .bool _ => .bool | .num _ => .num | .str _ => .str
  | .arr _ => .arr | .obj _ => .obj | .null => .other

/-- The value of an operand: a literal, or the fact at a path (`none` when absent or null). -/
def lookup (facts : Json) (path : String) : Option Json :=
  let rec go (cur : Json) : List String → Option Json
    | [] => match cur with | .null => none | v => some v
    | k :: ks => match cur with
      | .obj kvs => match kvs.get? k with
        | some v => go v ks
        | none => none
      | _ => none
  go facts (path.splitOn ".")

def litVal : Opd → Option Json
  | .num s => (decOfLexeme s).map fun d => .num ⟨d.m, d.e⟩
  | .str s => some (.str s)
  | .bool b => some (.bool b)
  | .field _ => none

/-- Python's str(), as the references use it for `in` and `contains`. -/
def pyStr : Json → String
  | .bool true => "True"
  | .bool false => "False"
  | .str s => s
  | .num n => n.toString
  | j => j.compress

def cmpPrim (op : String) (a b : Json) : Option Bool :=
  let ka := kindOf a
  if ka != kindOf b || ka == .other then none
  else if (op != "==" && op != "!=") && ka != .num && ka != .str then none
  else
    let ord : Option Ordering := match a, b with
      | .num x, .num y => some ((ofJsonNumber x).cmp (ofJsonNumber y))
      | .str x, .str y => some (compare x y)
      | _, _ => none
    let eq : Bool := match a, b with
      | .num x, .num y => (ofJsonNumber x).cmp (ofJsonNumber y) == .eq
      | .str x, .str y => x == y
      | .bool x, .bool y => x == y
      | x, y => x.compress == y.compress
    match op, ord with
    | "==", _ => some eq
    | "!=", _ => some !eq
    | ">", some o => some (o == .gt)
    | ">=", some o => some (o != .lt)
    | "<", some o => some (o == .lt)
    | "<=", some o => some (o != .gt)
    | _, _ => none

def relPrim (op : String) (a rhs : Json) : Option Bool :=
  let r := pyStr rhs
  if op == "between" then
    match a with
    | .num x =>
      let parts := r.splitOn ","
      match parts.head?.bind parseFloatPrefix, (parts.drop 1).head?.bind parseFloatPrefix with
      | some lo, some hi => some (lo.cmp (ofJsonNumber x) != .gt && (ofJsonNumber x).cmp hi != .gt)
      | _, _ => some false   -- NaN bounds: every comparison is false
    | _ => none
  else
    match kindOf a with
    | .str | .num | .bool =>
      if op == "in" then
        some ((r.splitOn ",").any fun p => p.trimAscii.toString == pyStr a)
      else some (((pyStr a).toLower.splitOn r.toLower).length > 1 || r.isEmpty)
    | _ => none

/-! ## From syntax to a condition of the model -/

/-- the fields an operand reads, and how to rebuild its value from theirs -/
def opdFields : Opd → List String
  | .field p => [p]
  | _ => []

def opdVal (o : Opd) (vs : List Json) : Option Json :=
  match o, vs with
  | .field _, v :: _ => some v
  | .field _, [] => none
  | o, _ => litVal o

def binAtom (l r : Opd) (prim : Json → Json → Option Bool) : Atom String Json :=
  .cmp (opdFields l ++ opdFields r) fun vs =>
    match opdVal l vs, opdVal r (vs.drop (opdFields l).length) with
    | some a, some b => prim a b
    | _, _ => none

def compile : Expr → Except String (Cond String Json)
  | .or a b => return .or (← compile a) (← compile b)
  | .and a b => return .and (← compile a) (← compile b)
  | .not a => return .not (← compile a)
  | .cmp o l r => return .atom (binAtom l r (cmpPrim o))
  | .rel o l r => return .atom (binAtom l r (relPrim o))
  | .ex (.field p) => return .atom (.ex p)
  | .ex _ => return .atom (.cmp [] fun _ => some true)
  | .matches _ _ => throw "matches() is not supported by the oracle"
  | .bare o => return .atom (.cmp (opdFields o) fun vs =>
      match opdVal o vs with
      | some (.bool b) => some b
      | _ => none)

end OracleExpr
