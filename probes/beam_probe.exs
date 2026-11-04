IO.puts("EMUDHRA_RUNTIME:" <> System.version())
for name <- [:certifi, :castore] do
  Application.load(name)
  case Application.spec(name, :vsn) do
    nil -> :ok
    version -> IO.puts("EMUDHRA_LIB:#{name}:#{version}")
  end
end
