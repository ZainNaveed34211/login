// Cloudflare Worker entry point for account-api.kluzar.com.
// D1 is accessed ONLY through the env.DB binding. No direct D1 URL exists.
import { handleRequest } from './handlers.js'

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env)
  },
}
export { handleRequest }
