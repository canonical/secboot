char shim_version[] __attribute__((section (".data.ident"))) =
	"UEFI SHIM\n"
	"$Version: " SHIM_VERSION " $\n"
	"$BuildMachine: Linux x86_64 x86_64 x86_64 GNU/Linux $\n"
	"$Commit: " SHIM_COMMIT " $\n";
