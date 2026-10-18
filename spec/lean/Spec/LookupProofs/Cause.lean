import Spec.LookupProofs.Timeout

/-!
# What a failure says of its cause

`AllServersFailed` rests on a server that failed the lookup, and `Timeout` on none (docs/design.md
§5, The cause of a failure; §16 decision 45). So a lookup that fails with `allServersFailed` holds
a cause, and a lookup that fails with `timeout` holds none. `init` gives both, and no event breaks
them, so each state that a lookup reaches has them.
-/
namespace Spec.Lookup

/-- What the error of a failed lookup says of its cause. -/
def CauseFits (s : State) : Prop :=
  s.stage = .failed →
    (s.err = .allServersFailed → s.cause.isSome = true) ∧ (s.err = .timeout → s.cause = none)

theorem advanceServer_fits (c : Config) (s : State) : CauseFits (advanceServer c s) := by
  unfold advanceServer CauseFits
  split
  · intro hf; exact absurd hf (fresh_ne_failed c)
  · split
    · intro hf; exact absurd hf (fresh_ne_failed c)
    · intro _
      cases s.cause <;> simp [fail]

theorem nextCandidate_fits (c : Config) (s : State) (b : Bool) :
    CauseFits (nextCandidate c s b) := by
  unfold nextCandidate CauseFits
  dsimp only
  split
  · intro hf; exact absurd hf (fresh_ne_failed c)
  · intro _
    simp only [fail]
    split <;> simp

theorem fail_fits (s : State) (e : Err) (h1 : e ≠ .allServersFailed) (h2 : e ≠ .timeout) :
    CauseFits (fail s e) := by
  simp [CauseFits, fail, h1, h2]

theorem poll_fits (c : Config) (s : State) (h : CauseFits s) : CauseFits (poll c s).1 := by
  unfold poll
  cases hs : s.stage <;> simp_all [CauseFits]

theorem onReply_fits (c : Config) (s : State) (stream : Bool) (r : Reply) (h : CauseFits s) :
    CauseFits (onReply c s stream r).1 := by
  have running : ∀ t : State, t.stage ≠ .failed → CauseFits t := fun t ht hf => absurd hf ht
  cases r with
  | unmatched => exact h
  | truncated =>
    simp only [onReply]
    split
    · exact nextCandidate_fits c s true
    · exact running _ (by simp)
  | answer => exact running _ (by simp [onReply])
  | cname =>
    simp only [onReply]
    split
    · exact fail_fits s .chainTooLong (by simp) (by simp)
    · exact running _ (fresh_ne_failed c)
  | nxdomain => exact nextCandidate_fits c s false
  | nodata => exact nextCandidate_fits c s true
  | servfail => exact advanceServer_fits c _
  | formerr =>
    simp only [onReply]
    split
    · exact running _ (fresh_ne_failed c)
    · exact advanceServer_fits c _
  | badcookie =>
    simp only [onReply]
    split
    · split
      · exact advanceServer_fits c _
      · exact running _ (by simp)
    · split
      · exact running _ (by simp)
      · exact running _ (fresh_ne_failed c)

/-- No event breaks what a failure says of its cause. -/
theorem step_fits (c : Config) (s : State) (e : Event) (h : CauseFits s) :
    CauseFits (step c s e).1 := by
  by_cases hend : ended s.stage = true
  · rw [ended_absorbing c s e hend]; exact h
  have running : ∀ t : State, t.stage ≠ .failed → CauseFits t := fun t ht hf => absurd hf ht
  cases e with
  | poll => exact poll_fits c s h
  | expire =>
    simp only [step]
    split
    · exact poll_fits c _ (advanceServer_fits c s)
    · exact poll_fits c s h
  | sent => cases hst : s.stage <;> simp_all [step, CauseFits]
  | sendFailed =>
    cases hst : s.stage <;> simp only [step, hst] <;>
      first | exact advanceServer_fits c s | exact h
  | tcpConnected => cases hst : s.stage <;> simp_all [step, CauseFits]
  | tcpFailed =>
    simp only [step]
    split
    · exact advanceServer_fits c _
    · exact h
  | requestFailed =>
    simp only [step]
    split
    · exact advanceServer_fits c _
    · exact h
  | reply r =>
    cases hst : s.stage <;> simp only [step, hst]
    all_goals first
      | exact onReply_fits c s _ r h
      | exact h
  | cancel =>
    simp only [step]
    split
    · exact h
    · exact fail_fits s .canceled (by simp) (by simp)

theorem init_fits (c : Config) : CauseFits (init c) := by
  unfold init
  split
  · exact fail_fits _ .noServers (by simp) (by simp)
  · intro hf; exact absurd hf (fresh_ne_failed c)

/-- A lookup that fails with `allServersFailed` holds the cause of the last server failure, and one
that fails with `timeout` holds none, whatever the caller tells it (§5, The cause of a failure;
§16 decision 45). -/
theorem failure_cause (c : Config) (es : List Event) : CauseFits (run c (init c) es) := by
  have key : ∀ (es : List Event) (t : State), CauseFits t → CauseFits (run c t es) := by
    intro es
    induction es with
    | nil => intro t h; exact h
    | cons e rest ih => intro t h; exact ih _ (step_fits c t e h)
  exact key es _ (init_fits c)

end Spec.Lookup
