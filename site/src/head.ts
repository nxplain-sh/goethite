import { absolute, site } from './site'

/** A page's title, description and canonical URL, for search engines and link previews. */
export function pageHead({
	title,
	description,
	path,
}: {
	title: string
	description?: string
	path: string
}) {
	const url = absolute(path)
	const content = description ?? site.description
	return {
		meta: [
			{ title: title === site.title ? title : `${title} | ${site.title}` },
			{ name: 'description', content },
			{ property: 'og:title', content: title },
			{ property: 'og:description', content },
			{ property: 'og:type', content: 'website' },
			{ property: 'og:url', content: url },
			{ property: 'og:site_name', content: site.title },
		],
		links: [{ rel: 'canonical', href: url }],
	}
}
