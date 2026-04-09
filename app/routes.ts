import { type RouteConfig, index, route } from "@react-router/dev/routes";

export default [
	index("routes/home.tsx"),
	route("keygen", "routes/keygen.tsx"),
] satisfies RouteConfig;
