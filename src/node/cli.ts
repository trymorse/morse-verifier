#!/usr/bin/env node
// npx @askmorse/verify: checks this Node can run it, then runs main.ts, which reads the arguments.
export {};

const [major] = process.versions.node.split(".").map(Number);
if (major < 24) {
	process.stderr.write(
		`@askmorse/verify needs Node 24 or later, and this is Node ${process.versions.node}.\nInstall a current Node (https://nodejs.org), or in GitHub Actions add actions/setup-node with node-version: 24, and run again.\n`,
	);
	process.exitCode = 2;
} else {
	const { main } = await import("./main.ts");
	process.exitCode = await main(process.argv.slice(2)).catch((e: unknown) => {
		process.stdout.write(
			`\nCould not finish: ${e instanceof Error ? e.message : String(e)}. Nothing is proven.\n`,
		);
		return 2;
	});
}
