// What plugins/markdown.ts turns a Markdown file into.
declare module '*.md' {
	const page: import('./docs').Doc
	export default page
}
