import '@fontsource-variable/space-grotesk'
import '@fontsource-variable/jetbrains-mono'
import './styles/tokens.css'
import './styles/app.css'

import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider } from '@tanstack/react-router'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import { ApiError } from './api/client'
import { clearToken } from './auth'
import { createAppRouter } from './router'

/** A 401 means the token is missing or no longer valid: sign in again. */
function onError(error: unknown) {
	if (error instanceof ApiError && error.status === 401) {
		clearToken()
		const { pathname, href } = router.state.location
		if (pathname !== '/login') {
			void router.navigate({ to: '/login', search: { redirect: href } })
		}
	}
}

const queryClient = new QueryClient({
	queryCache: new QueryCache({ onError }),
	mutationCache: new MutationCache({ onError }),
	defaultOptions: {
		queries: {
			retry: (failures, error) => !(error instanceof ApiError && error.status < 500) && failures < 2,
			staleTime: 1_000,
		},
	},
})

const router = createAppRouter(queryClient)

const root = document.getElementById('root')
if (root !== null) {
	createRoot(root).render(
		<StrictMode>
			<QueryClientProvider client={queryClient}>
				<RouterProvider router={router} />
			</QueryClientProvider>
		</StrictMode>,
	)
}
