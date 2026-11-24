import Lake
open Lake DSL

/-! The series' mechanized proofs, as one Lake package so they can import each other.
    Core library only. `lake build` checks everything. Each original file still checks alone
    with `lean <file>.lean`. -/
package papers

@[default_target]
lean_lib CarriedAuthority where
  srcDir := "carried-authority/lean"

@[default_target]
lean_lib Sufficiency where
  srcDir := "carried-authority/lean"

@[default_target]
lean_lib Resolution where
  srcDir := "resolution/lean"

@[default_target]
lean_lib Composition where
  srcDir := "resolution/lean"

@[default_target]
lean_lib Issuance where
  srcDir := "issuance/lean"

@[default_target]
lean_lib Completeness where
  srcDir := "carried-authority/lean"

@[default_target]
lean_lib Chain where
  srcDir := "carried-authority/lean"

@[default_target]
lean_lib Containment where
  srcDir := "carried-authority/lean"

/-! The oracle: the model's verdict, computed, as an executable that reads cases as JSON.
    Kept out of the proof libraries above, which stay core-only. -/
lean_lib OracleCore where
  srcDir := "oracle"

lean_exe oracle where
  srcDir := "oracle"
  root := `Main
