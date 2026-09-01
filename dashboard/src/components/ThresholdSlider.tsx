interface ThresholdSliderProps {
  value: number;
  onChange: (value: number) => void;
}

export function ThresholdSlider({ value, onChange }: ThresholdSliderProps) {
  return (
    <div class="card">
      <h2 class="card-title">Similarity threshold</h2>
      <div class="slider-row">
        <input
          type="range"
          min={0.85}
          max={0.95}
          step={0.01}
          value={value}
          aria-label="Similarity threshold"
          onInput={(e) => onChange(Number((e.target as HTMLInputElement).value))}
        />
        <span class="slider-value">{value.toFixed(2)}</span>
      </div>
      <p style={{ color: 'var(--text-faint)', fontSize: 12, margin: '12px 0 0' }}>
        Requests matching the dark list above this similarity are banned. Lower = stricter.
      </p>
    </div>
  );
}
