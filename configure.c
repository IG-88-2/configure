#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libconfig.h>
#include <argp.h>



struct parameter {
	const char *group;
	const char *name;
	int type;
};



struct arguments {
	char *config_base;
	char *admin_key;
	char *server_name;
	char *admin_secret;
	char *api_secret;
	char *token_auth_secret;
	char *log_prefix;
	char *interface;
	char *nat_1_1_mapping;

	char *rtp_port_range;
	char *ice_ignore_list;
	char *stun_server;
	int ws_port;
	int admin_ws_port;
	int token_auth;
	int session_timeout;
	int candidates_timeout;
	int reclaim_session_timeout;
	int log_to_stdout;

	int string_ids;
	int debug_level;
	int stun_port;
	int nice_debug;
	int keep_private_host;
	int full_trickle;
	int ice_lite;
	int ice_tcp;

	int ws;
	int wss;
	int wss_port;
	int admin_ws;
	int admin_wss;
	int admin_wss_port;
	char *cert_pem;
	char *cert_key;
};



static struct argp_option options[] = {

	// { "ws", 335, OPTION_ARG_OPTIONAL, 0 },
	// { "wss", 336, OPTION_ARG_OPTIONAL, 0 },
	// { "wss_port", 337, OPTION_ARG_OPTIONAL, 0 },
	// { "admin_ws", 338, OPTION_ARG_OPTIONAL, 0 },
	// { "admin_wss", 339, OPTION_ARG_OPTIONAL, 0 },
	// { "admin_wss_port", 340, OPTION_ARG_OPTIONAL, 0 },
	// { "cert_pem", 341, OPTION_ARG_OPTIONAL, 0 },
	// { "cert_key", 342, OPTION_ARG_OPTIONAL, 0 },
	
	{ "admin_key", 'q', OPTION_ARG_OPTIONAL, 0 },
	{ "string_ids", 'w', OPTION_ARG_OPTIONAL, 0 },
	{ "rtp_port_range", 'e', OPTION_ARG_OPTIONAL, 0 },
	{ "server_name", 'r', OPTION_ARG_OPTIONAL, 0 },
	{ "admin_secret", 't', OPTION_ARG_OPTIONAL, 0 },
	{ "api_secret", 'y', OPTION_ARG_OPTIONAL, 0 },
	{ "token_auth", 'u', OPTION_ARG_OPTIONAL, 0 },
	{ "token_auth_secret", 'i', OPTION_ARG_OPTIONAL, 0 },
	{ "session_timeout", 'o', OPTION_ARG_OPTIONAL, 0 },
	{ "candidates_timeout", 'p', OPTION_ARG_OPTIONAL, 0 },
	{ "reclaim_session_timeout", 'a', OPTION_ARG_OPTIONAL, 0 },
	{ "debug_level", 's', OPTION_ARG_OPTIONAL, 0 },
	{ "log_to_stdout", 'd', OPTION_ARG_OPTIONAL, 0 },
	{ "log_prefix", 'f', OPTION_ARG_OPTIONAL, 0 },
	{ "interface", 'g', OPTION_ARG_OPTIONAL, 0 },
	{ "stun_server", 'h', OPTION_ARG_OPTIONAL, 0 },
	{ "stun_port", 'j', OPTION_ARG_OPTIONAL, 0 },
	{ "nat_1_1_mapping", 'k', OPTION_ARG_OPTIONAL, 0 },
	{ "keep_private_host", 'l', OPTION_ARG_OPTIONAL, 0 },
	{ "full_trickle", 'z', OPTION_ARG_OPTIONAL, 0 },
	{ "ice_lite", 'x', OPTION_ARG_OPTIONAL, 0 },
	{ "config_base", 'c', OPTION_ARG_OPTIONAL, 0 },
	{ "ice_tcp", 'v', OPTION_ARG_OPTIONAL, 0 },
	{ "ws_port", 'b', OPTION_ARG_OPTIONAL, 0 },
	{ "admin_ws_port", 'n', OPTION_ARG_OPTIONAL, 0 },
	{ "ice_ignore_list", 'm', OPTION_ARG_OPTIONAL, 0 },

	{ "ws", 'A', OPTION_ARG_OPTIONAL, 0 },
	{ "wss", 'B', OPTION_ARG_OPTIONAL, 0 },
	{ "wss_port", 'C', OPTION_ARG_OPTIONAL, 0 },
	{ "admin_ws", 'D', OPTION_ARG_OPTIONAL, 0 },
	{ "admin_wss", 'E', OPTION_ARG_OPTIONAL, 0 },
	{ "admin_wss_port", 'F', OPTION_ARG_OPTIONAL, 0 },
	{ "cert_pem", 'G', OPTION_ARG_OPTIONAL, 0 },
	{ "cert_key", 'H', OPTION_ARG_OPTIONAL, 0 },

  	{ 0 }
};



static error_t parse_opt (int key, char *arg, struct argp_state *state) {
	struct arguments *arguments = state->input;

	switch (key) {
		case 'A':
			arguments->ws = atoi(arg);
			break;
		case 'B':
			arguments->wss = atoi(arg);
			break;
		case 'C':
			arguments->wss_port = atoi(arg);
			break;
		case 'D':
			arguments->admin_ws = atoi(arg);
			break;
		case 'E':
			arguments->admin_wss = atoi(arg);
			break;
		case 'F':
			arguments->admin_wss_port = atoi(arg);
			break;
		case 'G':
			arguments->cert_pem = arg;
			break;
		case 'H':
			arguments->cert_key = arg;
			break;
		case 'n':
			arguments->admin_ws_port = atoi(arg);
			break;
		case 'b':
			arguments->ws_port = atoi(arg);
			break;
		case 'c':
			arguments->config_base = arg;
			break;
		case 'q': 
			arguments->admin_key = arg;
			break;
	    case 'w': 
			arguments->string_ids = 1;
			break;
	    case 'e':
			arguments->rtp_port_range = arg;
			break;
	    case 'r': 
			arguments->server_name = arg;
			break;
	    case 't':
			arguments->admin_secret = arg;
			break;
		case 'y': 
			arguments->api_secret = arg;
			break;
		case 'u': 
			arguments->token_auth = 1;
			break;
		case 'i': 
			arguments->token_auth_secret = arg;
			break;
		case 'o': 
			arguments->session_timeout = atoi(arg);
			break;
		case 'p': 
			arguments->candidates_timeout = atoi(arg);
			break;
		case 'a':
			arguments->reclaim_session_timeout = atoi(arg);
			break;
		case 's': 
			arguments->debug_level = atoi(arg);
			break;
		case 'd':
			arguments->log_to_stdout = 1;
			break;
		case 'f': 
			arguments->log_prefix = arg;
			break;
		case 'g': 
			arguments->interface = arg;
			break;
		case 'h': 
			arguments->stun_server = arg;
			break;
		case 'j': 
			arguments->stun_port = atoi(arg);
			break;
		case 'z': 
			arguments->full_trickle = 1;
			break;
		case 'k': 
			arguments->nat_1_1_mapping = arg;
			break;
		case 'l': 
			arguments->keep_private_host = arg;
			break;
		case 'x': 
			arguments->ice_lite = arg;
			break;
		case 'v': 
			arguments->ice_tcp = arg;
			break;
		case 'm': 
			arguments->ice_ignore_list = arg;
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
};



static struct argp argp = { 
	options, 
	parse_opt, 
	0, 
	0 
};



char* join_path(char* base, char* path) {

	char *p = malloc(strlen(base) + strlen(path) + 2);
	
	strcpy( p, base );
	strcat( p, "/" ) ; 
	strcat( p, path );

	return p;

}



int main(int argc, char **argv) {
	
	printf("start - %d arguments \n", argc);
	
	struct arguments arguments = {
		.ws = 1,
		.ws_port = 0,
		.wss = 0,	
		.wss_port = 0,
		.admin_ws = 1,
		.admin_ws_port = 7188,
		.admin_wss = 0,
		.admin_wss_port = 7989,
		.cert_pem = NULL,
		.cert_key = NULL,

		.config_base = NULL,
		.admin_key = NULL,
		.server_name = NULL,
		.admin_secret = NULL,
		.api_secret = NULL,
		.token_auth_secret = NULL,
		.log_prefix = NULL,
		.interface = NULL,
		.nat_1_1_mapping = NULL,
		.token_auth = 0, 
		.session_timeout = 0,
		.candidates_timeout = 0,
		.reclaim_session_timeout = 0,
		.log_to_stdout = 0,
		.string_ids = 0,
		.full_trickle = 0,
		.debug_level = 4,
		.rtp_port_range = NULL,
		.stun_server = NULL,
		.stun_port = 0,
		.nice_debug = 1,
		.nat_1_1_mapping = NULL,
		.keep_private_host = 0,
		.full_trickle = 0,
		.ice_lite = 0,
		.ice_tcp = 0,
		.ice_ignore_list = NULL
	};
	config_t janus_videoroom_config;
	config_t janus_websockets_config;
	config_t janus_config;
	argp_parse(&argp, argc, argv, ARGP_NO_EXIT, 0, &arguments);
	
	char *janus_config_path = join_path(arguments.config_base, "janus.jcfg");
	char *janus_videoroom_config_path = join_path(arguments.config_base, "janus.plugin.videoroom.jcfg");
	char *janus_websockets_config_path = join_path(arguments.config_base, "janus.transport.websockets.jcfg");

	printf("janus_config_path - %s \n", janus_config_path);
	printf("janus_videoroom_config_path - %s \n", janus_videoroom_config_path);
	printf("janus_websockets_config_path - %s \n", janus_websockets_config_path);
	
	config_init(&janus_videoroom_config);
	config_init(&janus_websockets_config);
	config_init(&janus_config);
	
  	config_setting_t *root, *setting;
	
	if (!config_read_file(&janus_config, janus_config_path)) {
		fprintf(
			stderr, 
			"%s:%d - %s\n", 
			config_error_file(&janus_config), 
			config_error_line(&janus_config), 
			config_error_text(&janus_config)
		);
		config_destroy(&janus_config);
		config_destroy(&janus_websockets_config);
		config_destroy(&janus_videoroom_config);
		return EXIT_FAILURE;
	}

	if (!config_read_file(&janus_videoroom_config, janus_videoroom_config_path)) {
		fprintf(
			stderr, 
			"%s:%d - %s\n",
			config_error_file(&janus_videoroom_config), 
			config_error_line(&janus_videoroom_config),
			config_error_text(&janus_videoroom_config)
		);
		config_destroy(&janus_config);
		config_destroy(&janus_websockets_config);
		config_destroy(&janus_videoroom_config);
		return EXIT_FAILURE;
	}

	if (!config_read_file(&janus_websockets_config, janus_websockets_config_path)) {
		fprintf(
			stderr, 
			"%s:%d - %s\n",
			config_error_file(&janus_websockets_config), 
			config_error_line(&janus_websockets_config),
			config_error_text(&janus_websockets_config)
		);
		config_destroy(&janus_config);
		config_destroy(&janus_websockets_config);
		config_destroy(&janus_videoroom_config);
		return EXIT_FAILURE;
	}



	root = config_root_setting(&janus_config);
	setting = config_setting_get_member(root, "general");
	if (!setting) {
		setting = config_setting_add(root, "general", CONFIG_TYPE_GROUP);
	}
	config_setting_remove(setting, "ws");
	setting = config_setting_add(setting, "ws", CONFIG_TYPE_BOOL);

	if (arguments.ws) {
		config_setting_set_bool(setting, 1);
	} else {
		config_setting_set_bool(setting, 0);
	}
	printf("set ws to %d \n", arguments.ws);
	


	root = config_root_setting(&janus_config);
	setting = config_setting_get_member(root, "general");
	if (!setting) {
		setting = config_setting_add(root, "general", CONFIG_TYPE_GROUP);
	}
	config_setting_remove(setting, "wss");
	setting = config_setting_add(setting, "wss", CONFIG_TYPE_BOOL);

	if (arguments.wss) {
		config_setting_set_bool(setting, 1);
	} else {
		config_setting_set_bool(setting, 0);
	}
	printf("set wss to %d \n", arguments.wss);



	root = config_root_setting(&janus_config);
	setting = config_setting_get_member(root, "admin");
	if (!setting) {
		setting = config_setting_add(root, "admin", CONFIG_TYPE_GROUP);
	}
	config_setting_remove(setting, "admin_ws");
	setting = config_setting_add(setting, "admin_ws", CONFIG_TYPE_BOOL);

	if (arguments.admin_ws) {
		config_setting_set_bool(setting, 1);
	} else {
		config_setting_set_bool(setting, 0);
	}
	printf("set admin_ws to %d \n", arguments.admin_ws);



	root = config_root_setting(&janus_config);
	setting = config_setting_get_member(root, "admin");
	if (!setting) {
		setting = config_setting_add(root, "admin", CONFIG_TYPE_GROUP);
	}
	config_setting_remove(setting, "admin_wss");
	setting = config_setting_add(setting, "admin_wss", CONFIG_TYPE_BOOL);

	if (arguments.admin_wss) {
		config_setting_set_bool(setting, 1);
	} else {
		config_setting_set_bool(setting, 0);
	}
	printf("set admin_wss to %d \n", arguments.admin_wss);
	


	if (arguments.wss_port) {
		root = config_root_setting(&janus_websockets_config);
		setting = config_setting_get_member(root, "general");
		if (!setting) {
			setting = config_setting_add(root, "general", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "wss_port");
		setting = config_setting_add(setting, "wss_port", CONFIG_TYPE_INT);
  		config_setting_set_int(setting, arguments.wss_port);
		printf("set wss port to %d \n", arguments.wss_port);
	}
	
	if (arguments.admin_wss_port) {
		root = config_root_setting(&janus_websockets_config);
		setting = config_setting_get_member(root, "admin");
		if (!setting) {
			setting = config_setting_add(root, "admin", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "admin_wss_port");
		setting = config_setting_add(setting, "admin_wss_port", CONFIG_TYPE_INT);
  		config_setting_set_int(setting, arguments.admin_wss_port);
		printf("set admin wss port to %d \n", arguments.admin_wss_port);
	}
	
	if (arguments.cert_pem) {
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "certificates");
		if (!setting) {
			setting = config_setting_add(root, "certificates", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "cert_pem");
		setting = config_setting_add(setting, "cert_pem", CONFIG_TYPE_STRING);
  		config_setting_set_string(setting, arguments.cert_pem);
		printf("set cert_pem to %s \n", arguments.cert_pem);
	}

	if (arguments.cert_key) {
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "certificates");
		if (!setting) {
			setting = config_setting_add(root, "certificates", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "cert_key");
		setting = config_setting_add(setting, "cert_key", CONFIG_TYPE_STRING);
  		config_setting_set_string(setting, arguments.cert_key);
		printf("set cert_key to %s \n", arguments.cert_key);
	}
	
	if (arguments.log_prefix) {
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "general");
		if (!setting) {
			setting = config_setting_add(root, "general", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "log_prefix");
		setting = config_setting_add(setting, "log_prefix", CONFIG_TYPE_STRING);
  		config_setting_set_string(setting, arguments.log_prefix);
		printf("set log prefix to %s \n", arguments.log_prefix);
	}

	if (arguments.ws_port) {
		root = config_root_setting(&janus_websockets_config);
		setting = config_setting_get_member(root, "general");
		if (!setting) {
			setting = config_setting_add(root, "general", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "ws_port");
		setting = config_setting_add(setting, "ws_port", CONFIG_TYPE_INT);
  		config_setting_set_int(setting, arguments.ws_port);
		printf("set ws port to %d \n", arguments.ws_port);
	}

	if (arguments.admin_ws_port) {
		root = config_root_setting(&janus_websockets_config);
		setting = config_setting_get_member(root, "admin");
		if (!setting) {
			setting = config_setting_add(root, "admin", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "admin_ws_port");
		setting = config_setting_add(setting, "admin_ws_port", CONFIG_TYPE_INT);
  		config_setting_set_int(setting, arguments.admin_ws_port);
		printf("set admin ws port to %d \n", arguments.admin_ws_port);
	}

	if (arguments.admin_key) {
		root = config_root_setting(&janus_videoroom_config);
		setting = config_setting_get_member(root, "general");
		if (!setting) {
			setting = config_setting_add(root, "general", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "admin_key");
		setting = config_setting_add(setting, "admin_key", CONFIG_TYPE_STRING);
  		config_setting_set_string(setting, arguments.admin_key);
		printf("set admin key to %s \n", arguments.admin_key);
	}

	if (arguments.string_ids) {
		root = config_root_setting(&janus_videoroom_config);
		setting = config_setting_get_member(root, "general");
		if (!setting) {
			setting = config_setting_add(root, "general", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "string_ids");
		setting = config_setting_add(setting, "string_ids", CONFIG_TYPE_BOOL);
		config_setting_set_bool(setting, arguments.string_ids);
		printf("set string_ids to %d \n", arguments.string_ids);
	}
	
	if (arguments.server_name) {
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "general");
		if (!setting) {
			setting = config_setting_add(root, "general", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "server_name");
		setting = config_setting_add(setting, "server_name", CONFIG_TYPE_STRING);
		config_setting_set_string(setting, arguments.server_name);
		printf("set server_name to %s \n", arguments.server_name);
	}

	if (arguments.admin_secret) {
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "general");
		if (!setting) {
			setting = config_setting_add(root, "general", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "admin_secret");
		setting = config_setting_add(setting, "admin_secret", CONFIG_TYPE_STRING);
		config_setting_set_string(setting, arguments.admin_secret);
		printf("set admin_secret to %s \n", arguments.admin_secret);
	}
	
	if (arguments.debug_level) {
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "general");
		if (!setting) {
			setting = config_setting_add(root, "general", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "debug_level");
		setting = config_setting_add(setting, "debug_level", CONFIG_TYPE_INT);
		config_setting_set_int(setting, arguments.debug_level);
		printf("set debug_level to %d \n", arguments.debug_level);
	}

	if (arguments.rtp_port_range) {
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "media");
		if (!setting) {
			setting = config_setting_add(root, "media", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "rtp_port_range");
		setting = config_setting_add(setting, "rtp_port_range", CONFIG_TYPE_STRING);
		config_setting_set_string(setting, arguments.rtp_port_range);
		printf("set rtp_port_range to %s \n", arguments.rtp_port_range);
	}
	
	if (arguments.stun_server) {
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "nat");
		if (!setting) {
			setting = config_setting_add(root, "nat", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "stun_server");
		setting = config_setting_add(setting, "stun_server", CONFIG_TYPE_STRING);
		config_setting_set_string(setting, arguments.stun_server);
		printf("set stun_server to %s \n", arguments.stun_server);
	}

	if (arguments.stun_port) {
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "nat");
		if (!setting) {
			setting = config_setting_add(root, "nat", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "stun_port");
		setting = config_setting_add(setting, "stun_port", CONFIG_TYPE_INT);
		config_setting_set_int(setting, arguments.stun_port);
		printf("set stun_port to %d \n", arguments.stun_port);
	}
	
	if (arguments.nat_1_1_mapping) {
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "nat");
		if (!setting) {
			setting = config_setting_add(root, "nat", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "nat_1_1_mapping");
		setting = config_setting_add(setting, "nat_1_1_mapping", CONFIG_TYPE_STRING);
		config_setting_set_string(setting, arguments.nat_1_1_mapping);
		printf("set nat_1_1_mapping to %s \n", arguments.nat_1_1_mapping);
	}
	
	if (arguments.keep_private_host) {
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "nat");
		if (!setting) {
			setting = config_setting_add(root, "nat", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "keep_private_host");
		setting = config_setting_add(setting, "keep_private_host", CONFIG_TYPE_BOOL);
		config_setting_set_bool(setting, arguments.keep_private_host);
		printf("set keep_private_host to %d \n", arguments.keep_private_host);
	}
	
	if (arguments.full_trickle) {
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "nat");
		if (!setting) {
			setting = config_setting_add(root, "nat", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "full_trickle");
		setting = config_setting_add(setting, "full_trickle", CONFIG_TYPE_INT);
		config_setting_set_int(setting, arguments.full_trickle);
		printf("set full_trickle to %d \n", arguments.full_trickle);
	}
	
	if (arguments.ice_lite) {
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "nat");
		if (!setting) {
			setting = config_setting_add(root, "nat", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "ice_lite");
		setting = config_setting_add(setting, "ice_lite", CONFIG_TYPE_INT);
		config_setting_set_int(setting, arguments.ice_lite);
		printf("set ice_lite to %d \n", arguments.ice_lite);
	}
	
	if (arguments.ice_tcp) {
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "nat");
		if (!setting) {
			setting = config_setting_add(root, "nat", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "ice_tcp");
		setting = config_setting_add(setting, "ice_tcp", CONFIG_TYPE_INT);
		config_setting_set_int(setting, arguments.ice_tcp);
		printf("set ice_tcp to %d \n", arguments.ice_tcp);
	}
	
	if (arguments.ice_ignore_list) {
		//ice_ignore_list = "vmnet,192.168."
		root = config_root_setting(&janus_config);
		setting = config_setting_get_member(root, "nat");
		if (!setting) {
			setting = config_setting_add(root, "nat", CONFIG_TYPE_GROUP);
		}
		config_setting_remove(setting, "ice_ignore_list");
		setting = config_setting_add(setting, "ice_ignore_list", CONFIG_TYPE_STRING);
		config_setting_set_string(setting, arguments.ice_ignore_list);
		printf("set ice_ignore_list to %s \n", arguments.ice_ignore_list);
	}

 	if (
		!config_write_file(&janus_config, janus_config_path) ||
		!config_write_file(&janus_videoroom_config, janus_videoroom_config_path) ||
		!config_write_file(&janus_websockets_config, janus_websockets_config_path)
	) {
		fprintf(stderr, "Error while writing file.\n");
		config_destroy(&janus_videoroom_config);
		config_destroy(&janus_websockets_config);
		config_destroy(&janus_config);
		return EXIT_FAILURE;
	}

	fprintf(stderr, "Configuration successfully updated \n");

	config_destroy(&janus_videoroom_config);
	config_destroy(&janus_websockets_config);
	config_destroy(&janus_config);
	
	free(janus_config_path);
	free(janus_videoroom_config_path);
	free(janus_websockets_config_path);

	return EXIT_SUCCESS;
}
