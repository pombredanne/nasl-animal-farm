"""
Plugin File
"""

import re

def _get_stack_top(stack):
    """Conditionally returns the top of a stack or an empty string"""
    if stack and len(stack) > 0:
        return stack[len(stack) - 1] 
    else:
        return ''


def _set_stack_top(stack, value):
    """Conditionally sets the value of the top item on the stack or push a new item to an empty stack"""
    if _get_stack_top(stack) == '':
        stack.append(value) 
    else:
        stack[len(stack) - 1] = value


class Plugin():
    """Plugin File"""

    tok_constants = {
        '\'': 'S_QUOTE',
        '"' : 'D_QUOTE',
        '(' : 'L_PAREN',
        ')' : 'R_PAREN',
        '{' : 'L_BRACE',
        '}' : 'R_BRACE',
        '#' : 'COMMENT',
        'if' : 'IF',
        'include' : 'INCLUDE',
        '!' : 'NOT',
        'while' : 'WHILE',
        'for' : 'FOR',
        '-=' : 'MINUSEQ',
        '+=' : 'PLUSEQ',
        '&&' : 'AND',
        '||' : 'OR',
        '[' : 'L_BRACKET',
        ']' : 'R_BRACKET',
        '.' : 'DOT',
        '-' : 'MINUS',
        '+' : 'PLUS',
        '*' : 'TIMES',
        '/' : 'DIVIDE',
        '=' : 'EQUALS',
        ':' : 'COLON',
        ';' : 'SEMICOLON',
        ',' : 'COMMA',
        '\\': 'ESCAPE',
        'foreach' : 'FOREACH',
        'namespace' : 'NAMESPACE',
        'object' : 'OBJECT', 
        'include' : 'INCLUDE',
        'function' : 'FUNCTION'
    }

    built_ins = {
        "script_name",
        "script_version",
        "script_timeout",
        "script_description",
        "script_copyright",
        "script_summary",
        "script_category",
        "script_family",
        "script_dependencie",
        "script_dependencies",
        "script_require_keys",
        "script_require_ports",
        "script_require_udp_ports",
        "script_exclude_keys",
        "script_add_preference",
        "script_get_preference",
        "script_get_preference_file_content",
        "script_get_preference_file_location",
        "script_id",
        "script_cve_id",
        "script_bugtraq_id",
        "script_xref",
        "get_preference",
        "safe_checks",
        "replace_kb_item",
        "set_kb_item",
        "get_kb_item",
        "get_kb_fresh_item",
        "get_kb_list",
        "security_warning",
        "security_note",
        "security_hole",
        "scanner_add_port",
        "scanner_status",
        "scanner_get_port",
        "open_sock_tcp",
        "open_sock_udp",
        "open_priv_sock_tcp",
        "open_priv_sock_udp",
        "recv",
        "recv_line",
        "send",
        "close",
        "join_multicast_group",
        "leave_multicast_group",
        "get_source_port",
        "cgibin",
        "is_cgi_installed",
        "http_open_socket",
        "http_head",
        "http_get",
        "http_post",
        "http_delete",
        "http_put",
        "http_close_socket",
        "get_host_name",
        "get_host_ip",
        "same_host",
        "get_host_open_port",
        "get_port_state",
        "get_tcp_port_state",
        "get_udp_port_state",
        "islocalhost",
        "islocalnet",
        "get_port_transport",
        "this_host",
        "this_host_name",
        "string",
        "raw_string",
        "strcat",
        "display",
        "ord",
        "hex",
        "hexstr",
        "strstr",
        "ereg",
        "ereg_replace",
        "egrep",
        "eregmatch",
        "match",
        "substr",
        "insstr",
        "tolower",
        "toupper",
        "crap",
        "strlen",
        "split",
        "chomp",
        "int",
        "stridx",
        "str_replace",
        "make_list",
        "make_array",
        "keys",
        "max_index",
        "sort",
        "unixtime",
        "gettimeofday",
        "localtime",
        "mktime",
        "open_sock_kdc",
        "start_denial",
        "end_denial",
        "dump_ctxt",
        "typeof",
        "exit",
        "rand",
        "usleep",
        "sleep",
        "isnull",
        "defined_func",
        "forge_ip_packet",
        "get_ip_element",
        "set_ip_elements",
        "insert_ip_options",
        "dump_ip_packet",
        "forge_tcp_packet",
        "get_tcp_element",
        "set_tcp_elements",
        "dump_tcp_packet",
        "tcp_ping",
        "forge_udp_packet",
        "get_udp_element",
        "set_udp_elements",
        "dump_udp_packet",
        "forge_icmp_packet",
        "get_icmp_element",
        "forge_igmp_packet",
        "send_packet",
        "pcap_next",
        "send_capture",
        "MD2",
        "MD4",
        "MD5",
        "SHA",
        "SHA1",
        "RIPEMD160",
        "HMAC_MD2",
        "HMAC_MD5",
        "HMAC_SHA",
        "HMAC_SHA1",
        "HMAC_DSS",
        "HMAC_RIPEMD160",
        "dh_generate_key",
        "bn_random",
        "bn_cmp",
        "dh_compute_key",
        "rsa_public_decrypt",
        "bf_cbc_encrypt",
        "bf_cbc_decrypt",
        "dsa_do_verify",
        "pem_to_rsa",
        "pem_to_dsa",
        "rsa_sign",
        "dsa_do_sign",
        "pread",
        "find_in_path",
        "fread",
        "fwrite",
        "unlink",
        "get_tmp_dir",
        "file_stat",
        "file_open",
        "file_close",
        "file_read",
        "file_write",
        "file_seek",
        "prompt",
        "get_local_mac_addrs",
        "func_has_arg",
        "socket_get_error",
        "big_endian",
        "socket_ready",
        "socket_negotiate_ssl",
        "socket_pending",
        "fill_list",
        "zlib_compress",
        "zlib_decompress",
        "fork",
        "bsd_byte_ordering",
        "inject_packet",
        "get_local_mac_addr",
        "get_gw_mac_addr",
        "prompt_password",
        "disable_all_plugins",
        "enable_plugin_family",
        "disable_plugin_family",
        "enable_plugin_id",
        "disable_plugin_id",
        "#nasl_str2intarray",
        "rm_kb_item",
        "get_host_raw_ip",
        "this_host_raw",
        "aes_cbc_encrypt",
        "aes_cbc_decrypt",
        "tripledes_cbc_encrypt",
        "tripledes_cbc_decrypt",
        "file_is_signed",
        "bind_sock_tcp",
        "bind_sock_udp",
        "sock_accept",
        "make_path",
        "start_trace",
        "stop_trace",
        "rsa_public_encrypt",
        "rsa_private_encrypt",
        "rsa_private_decrypt",
        "bn_dec2raw",
        "bn_raw2dec",
        "bn_hex2raw",
        "bn_raw2hex",
        "tcp_scan",
        "socketpair",
        "syn_scan",
        "platform",
        "xmlparse",
        "preg",
        "pgrep",
        "pregmatch",
        "udp_scan",
        "get_global_kb_list",
        "set_global_kb_item",
        "get_global_kb_item",
        "open_sock2",
        "mutex_lock",
        "mutex_unlock",
        "uint",
        "aes_ctr_encrypt",
        "aes_ctr_decrypt",
        "set_mem_limits",
        "report_xml_tag",
        "script_set_attribute",
        "script_end_attributes",
        "datalink",
        "link_layer",
        "sendto",
        "recvfrom",
        "bpf_open",
        "bpf_close",
        "bpf_next",
        "bn_add",
        "bn_sub",
        "bn_mul",
        "bn_sqr",
        "bn_div",
        "bn_mod",
        "bn_nnmod",
        "bn_mod_add",
        "bn_mod_sub",
        "bn_mod_mul",
        "bn_mod_sqr",
        "bn_exp",
        "bn_mod_exp",
        "bn_gcd",
        "readdir",
        "ssl_accept",
        "resolv",
        "open_sock_proxy",
        "get_peer_name",
        "nessus_get_dir",
        "rename",
        "get_sock_name",
        "shutdown",
        "debug_exit",
        "aes_cfb_encrypt",
        "aes_cfb_decrypt",
        "routethrough",
        "socket_set_timeout",
        "file_mtime",
        "mkdir",
        "rmdir",
        "ssl_accept2",
        "gzip_compress",
        "deflate_compress",
        "wait",
        "getpid",
        "query_report",
        "can_query_report",
        "xslt_apply_stylesheet",
        "platform_ptr_size",
        "kill",
        "nasl_level",
        "SHA224",
        "SHA256",
        "SHA512",
        "HMAC_SHA224",
        "HMAC_SHA256",
        "HMAC_SHA512",
        "query_scratchpad",
        "ssl_accept3",
        "ssl_get_peer_name",
        "pem_to_rsa2",
        "pem_to_dsa2",
        "cfile_open",
        "file_fstat",
        "cfile_stat",
        "mktime_tz",
        "gettimezones",
        "getlocaltimezone",
        "report_error",
        "security_low",
        "security_critical",
        "ipsort",
        "numsort",
        "bind_sock_tcp6",
        "bind_sock_udp6",
        "security_report",
        "nasl_base64_decode",
        "nasl_base64_encode",
        "get_var",
        "set_var",
        "get_global_var",
        "set_global_var",
        "htmlparse",
        "bzip2_compress",
        "bzip2_decompress",
        "db_open",
        "db_close",
        "db_query",
        "db_query_foreach",
        "jpeg_image",
        "buffer_pick",
        "security_report_with_attachments",
        "nc_encode_array",
        "nc_encode_xml",
        "db_copy",
        "load_db_master_key_cli",
        "is_user_root",
        "dump_interfaces",
        "untar_plugins",
        "mkcert",
        "get_cert_dname",
        "mkdir_ex",
        "chmod",
        "typeof_ex",
        "new",
        "delete",
        "tickcount",
        "serialize",
        "deserialize",
        "socket_get_secure_renegotiation_support",
        "SHA384",
        "HMAC_SHA384",
        "insert_element",
        "delete_element",
        "fork_ex",
        "abort",
        "nasl_environment",
        "equals",
        "db_open2",
        "close_handle",
        "open_sock_ex",
        "socket_negotiate_ssl_ex",
        "mutex_get_info",
        "pem_to_pub_rsa",
        "ssl_validate",
        "db_passwd2key",
        "tar_files",
        "threaded_delay",
        "stack_dump",
        "gettime",
        "event_add",
        "event_remove",
        "#synchonize",
        "ssl_get_encaps",
        "append_element",
        "contains_element",
        "format",
        "db_open_ex",
        "random",
        "gc",
        "ssl_get_error",
        "ssl_set_alpn_protocols",
        "ssl_get_alpn_protocol",
        "trim",
        "ssl_get_session_key",
        "rules_validate_target",
        "rules_validate_plugin",
        "get_preference_file_content",
        "get_fork_perf",
        "sched_dump",
        "inject_host",
        "report_tag_internal",
        "send_file",
        "recv_file",
        "is_sock_open",
        "file_stat_ex",
        "system_log_register",
        "system_log",
        "system_log_count",
        "system_log_empty",
        "get_host_fqdn",
        "recv_until_boundary",
        "db_dump",
        "file_hash",
        "rsa_generate",
        "bn_mod_inverse",
        "ecc_scalar_multiply",
        "ecc_curve_details",
        "crypto_hash",
        "crypto_mac",
        "crypto_encrypt",
        "crypto_decrypt",
        "xsd_validate",
        "schematron_validate",
        "xmldsig_verify",
        "xmldsig_sign",
        "xslt_filter",
        "report_xml_tag2",
        "get_local_ifaces",
        "gzip_deflate_init",
        "gzip_deflate",
        "gzip_deflate_end",
        "make_list2",
        "localtime_tz",
        "gzip_inflate_init",
        "gzip_inflate",
        "gzip_inflate_end",
        "ssl_accept4",
        "get_host_report_name",
        "set_socket_option",
        "get_socket_option",
        "create_plugin_db",
        "server_authenticate",
        "server_is_user_admin",
        "server_add_user",
        "server_delete_user",
        "server_user_chpasswd",
        "server_list_users",
        "server_feed_type",
        "server_generate_token",
        "server_validate_token",
        "server_delete_token",
        "server_get_plugin_list",
        "server_get_plugin_preferences_list",
        "server_get_plugin_description",
        "server_get_preferences",
        "server_scan_list",
        "server_list_reports",
        "server_report_get_host_list",
        "server_report_get_port_list",
        "server_report_get_port_details",
        "server_get_plugin_list_family",
        "server_report_get_tags",
        "server_scan_ctrl",
        "server_report_delete",
        "server_restart",
        "server_import_nessus_file",
        "server_get_plugins_md5",
        "server_get_load",
        "server_get_plugin_list_matching_families",
        "server_user_exists",
        "socket_redo_ssl_handshake",
        "socket_reset_ssl",
        "server_get_status",
        "server_master_unlock",
        "server_get_plugins_descriptions",
        "server_scan_get_status",
        "server_loading_progress",
        "server_query_report",
        "server_report_get_trail_details",
        "server_report_get_host_list2",
        "server_report_get_port_list2",
        "server_report_get_port_details2",
        "server_report_get_vuln_list2",
        "server_untar_plugins",
        "server_plugin_search_attributes",
        "server_plugin_search_matching_families",
        "server_plugin_search_matching_plugins",
        "server_report_get_kb",
        "server_report_has_audit_trail",
        "server_report_has_kb",
        "server_report_regenerate",
        "server_report_search_attributes",
        "server_report_get_port_details_plugin",
        "server_report_get_host_list_plugin",
        "server_report_num_scan_errors",
        "server_report_scan_errors",
        "server_get_global_preferences",
        "server_set_global_preferences",
        "server_distribution",
        "server_token_retain",
        "server_token_release",
        "server_log",
        "server_report_export",
        "server_report_import",
        "server_generate_dot_nessus",
        "server_token_update",
        "file_md5",
        "server_launch_scan",
        "server_insert_policy",
        "server_set_dynamic_rules",
        "server_set_master_password",
        "server_needs_master_password",
        "winreg_openkey",
        "winreg_queryinfokey",
        "winreg_queryvalue",
        "winreg_enumvalue",
        "winreg_enumkey",
        "winreg_getkeysecurity",
        "winreg_createkey",
        "winreg_setvalue",
        "winfile_localpath",
        "winfile_create",
        "winfile_read",
        "winfile_write",
        "winfile_size",
        "winfile_delete",
        "winfile_versioninfo",
        "winfile_versioninfo_ex",
        "winfile_securityinfo",
        "winfile_findfirst",
        "winfile_findnext",
        "winwmi_connectserver",
        "winwmi_execquery",
        "winwmi_getnextelement",
        "winwmi_getobject",
        "winwmi_spawninstance",
        "winwmi_execmethod",
        "winlsa_open_policy",
        "winlsa_query_info",
        "winlsa_query_domain_info",
        "winlsa_lookup_sids",
        "winlsa_lookup_names",
        "winlsa_enumerate_accounts",
        "winsvc_open_manager",
        "winsvc_open",
        "winsvc_enum_status",
        "winsvc_control",
        "winsvc_create",
        "winsvc_start",
        "winsvc_delete",
        "winsvc_query_status",
        "winsvc_get_displayname",
        "winsvc_query_security",
        "winnet_get_server_info",
        "winnet_get_wksta_info",
        "winnet_enum_sessions",
        "winnet_enum_shares",
        "winnet_enum_wksta_users",
        "winnet_enum_servers",
        "winnet_get_user_groups",
        "winnet_get_user_local_groups",
        "winnet_get_local_group_members",
        "winnet_get_group_users",
        "winnet_get_user_info",
        "winnet_get_user_modals"
    }

    def __init__(self, filename):
        parts = filename.split('.')
        last_part = len(parts) - 1

        if last_part < 1 or not (parts[last_part] == "nasl" or parts[last_part] == "inc"):
            raise Exception("Supplied file has the wrong extension '." + parts[last_part] +
                            "' to be a NASL plugin or include")

        self.file = filename
        self.parsed = False
        self.parse_tree = []
        self.f_stack = []
        self.s_stack = []
        self.parse_fn = None


    def _tokenize(self, line):
        """Takes one line of NASL code and returns a list of tuples"""
        """[token type, token value]"""
        words = re.split('(?:\s+)|([\(\)\'"{}#!\[\]\.+\-*/,:\\\\])', line)
        tokens = [[None, word] for word in words if word]
        for token in tokens:
            if token[1] in self.tok_constants:
                token[0] = self.tok_constants[token[1]]
            else:
                token[0] = 'LITERAL'
 
        return tokens


    #A fancy way to ignore includes
    def _parse_include(self, working_tree, state, token):
        """Recognizes an include                                             """
        if not 'in_paren' in state:
          state['in_paren'] = False

        if not state['in_paren']:
            if token[0] == 'L_PAREN':
                state['in_paren'] = True
            elif token[0] == 'SEMICOLON':
                state.clear()
                self.parse_fn = f_stack.pop()
        else:
            if token[0] == 'R_PAREN':
                state['in_paren'] = False

        return working_tree


    def _parse_function_call(self, working_tree, state, token):
        """Recognize a NASL function call                                    """

        if 'maybe_fn_name' in state and not state['maybe_fn_name'] == '' :
            if token[0] == 'L_PAREN':
                state['fn_name'].append(state['maybe_fn_name'])
                self.f_stack.append(self._parse_function_call)
                state['maybe_fn_name'] = ''

            state['maybe_fn_name'] = ''

        if token[0] == 'R_PAREN':
            working_tree.append(['FN_CALL', _get_stack_top(state['fn_name'])])
            state['fn_name'].pop()
            self.parse_fn = self.f_stack.pop()

        elif token[0] == 'LITERAL':
            state['maybe_fn_name'] = token[1]

        return working_tree


    def _parse_code_body(self, working_tree, state, token, source):
        """Recognize a normal NASL code block                                """
        if not 'fn_name' in state:
            state['fn_name'] = []

        if not 'in_block' in state:
            state['in_block'] = 0
            state['ignore'] = 0

        if 'maybe_fn_name' in state  and len(state['maybe_fn_name']) > 0:
            if token[0] == 'L_PAREN':
                state['fn_name'].append(state['maybe_fn_name'])
                self.f_stack.append(source)
                self.parse_fn = self._parse_function_call

            state['maybe_fn_name'] = ''

        if token[0] == 'LITERAL':
            if state['ignore'] == 0:
              state['maybe_fn_name'] = token[1]
            else:
              state['ignore'] = 0
        elif token[0] == 'L_BRACE':
            state['in_block'] += 1
        elif token[0] == 'R_BRACE':
            if state['in_block'] > 0:
                state['in_block'] -= 1
            else: 
                state.clear()
                self.parse_fn = self.f_stack.pop()
                working_tree = self.s_stack.pop()
        elif token[0] == 'FOREACH':
            state['ignore'] = 1


        return working_tree


    def _parse_function_def(self, working_tree, state, token):
        """Recognize a NASL function definition                              """
        if not 'in_part' in state:
            state['in_part'] = 'start'
            state['f_call_name'] = ''

        if token[0] == 'L_PAREN' and len(state['f_call_name']) > 0:
            state['in_part'] = 'args'
        elif token[0] == 'R_PAREN' and state['in_part'] == 'args':
            state['in_part'] = 'after args'
        elif token[0] == 'L_BRACE' and state['in_part'] == 'after args':
            scope = []
            working_tree.append(['FN_DEF', state['f_call_name'], scope])
            self.s_stack.append(working_tree)
            working_tree = scope
            state['f_call_name'] = ''
            state['in_part'] = 'def'
        # NASL can redefine built-ins
        elif token[0] == 'LITERAL' and state['in_part'] == 'start':
            state['f_call_name'] = token[1]
        elif state['in_part'] == 'def':
            return self._parse_code_body(working_tree, state, token, self._parse_function_def)

        return working_tree


    def _parse_scope_keyword(self, working_tree, state, token):
        """Recognize the NASL keywords that create function scope            """
        if not 'in_part' in state:
            state['in_part'] = 'start'

        if token[0] == 'R_BRACE' and state['in_part'] == 'start':
            state.clear()
            self.parse_fn = self.f_stack.pop()
            working_tree = self.s_stack.pop()
            return working_tree
        elif token[0] == 'L_BRACE':
            if 'scope_name' in state and state['in_part'] == 'start':
                scope = []
                working_tree.append([state['scope_type'], state['scope_name'], scope])
                self.s_stack.append(working_tree)
                working_tree = scope
                self.f_stack.append(self._parse_scope_keyword)
                state['in_part'] = 'in-scope'
        elif token[0] == 'LITERAL' and state['in_part'] == 'start':
            if 'scope_type' in state:
                state['scope_name'] = token[1]
            else:
                state['in_part'] = 'in-scope'
        elif token[0] == 'NAMESPACE' or token[0] == 'OBJECT':
            state.clear()
            state['scope_type'] = token[0]
            state['in_part'] = 'start'
        elif token[0] == 'FUNCTION':
            state.clear()
            state['scope_type'] = token[0]
            self.f_stack.append(self._parse_scope_keyword)
            self.parse_fn = self._parse_function_def

        if not 'in_part' in state or state['in_part'] == 'in-scope':
            return self._parse_code_body(working_tree, state, token, self._parse_scope_keyword)
        else:
            return working_tree


    def _parse_top_level(self, working_tree, state, token):
        """Recognizes and processeses top level NASL constructs              """
        """and delegates to the correct lower level handler.                 """
        if token[0] == 'include':
            self.f_stack.append(self._parse_top_level)
            self.parse_fn = self._parse_include
            return working_tree
        elif token[0] == 'NAMESPACE' or token[0] == 'OBJECT':
            state['scope_type'] = token[0]
            self.f_stack.append(self._parse_top_level)
            self.parse_fn = self._parse_scope_keyword
            return working_tree
        elif token[0] == 'FUNCTION':
            state.clear()
            self.f_stack.append(self._parse_top_level)
            self.parse_fn = self._parse_function_def
            return working_tree


        return self._parse_code_body(working_tree, state, token, self._parse_top_level)


    def _parse(self, nasl):
        """Creates a crude parse tree of the plugin file.                    """
        """                                                                  """
        """ Obviously this approach won't work with function references or   """
        """ the like.                                                        """
        working_tree = self.parse_tree
        self.parse_fn = self._parse_top_level

        in_double_quote = False
        in_single_quote = False
        in_escape = False

        state = {}

        try:
            for line in nasl:
                for token in self._tokenize(line):
                   #Stop processing a line when a comment is encountered
                   if not in_single_quote and not in_double_quote and token[0] == 'COMMENT':
                       break 

                   if token[0] == 'D_QUOTE' and not in_single_quote and not in_escape:
                       if in_double_quote:
                           in_double_quote = False
                       else:
                           in_double_quote = True

                   if token[0] == 'S_QUOTE' and not in_double_quote and not in_escape:
                       if in_single_quote:
                           in_single_quote = False
                       else:
                           in_single_quote = True

                   if in_escape:
                       in_escape = False
                       if token[0] == 'ESCAPE':
                           token[0] = 'BSLASH'

                   #Ignore quoted strings
                   if in_double_quote or in_single_quote:
                       if in_single_quote and token[0] == 'ESCAPE':
                           in_escape = True
                       continue

                   working_tree = self.parse_fn(working_tree, state, token)

            self.parsed = True

        #Some Nasl files are binary encoded and can't be parsed.  Silently ignore them
        except UnicodeDecodeError as err:
            self.parse_tree = []
 
        return self.parse_tree


    def get_plugin_name(self) -> str:
        """Returns the plugin name"""
        return self.file


    def _traverse(self, parse_tree, predicate, scope) -> list:
        result = set()
        for item in parse_tree:
            if item[0] == "OBJECT" or item[0] == "NAMESPACE":
                result = result.union(self._traverse(item[2], predicate, scope + "::" + item[1]))
            elif item[0] == "FN_DEF":
                result = result.union(self._traverse(item[2], predicate, scope + ":" + item[1]))

            if predicate(item):
                if len(scope) > 0:
                    result.add(scope + "?" +  item[1])
                else:
                    result.add("::" + item[1])

        return result


    def get_function_calls(self) -> list:
        """Returns a list of functions called by this plugin"""
        tree = []
        if not self.parsed:
            with open(self.file, "r") as nasl:
                self._parse(nasl)
        return self._traverse(self.parse_tree, lambda x: x[0] == "FN_CALL", "")

    def get_function_defs(self) -> list:
        """Returns a list of function definitions in this plugin or include"""
        tree = []
        if not self.parsed:
            with open(self.file, "r") as nasl:
                self._parse(nasl)
        return self._traverse(self.parse_tree, lambda x: x[0] == "FN_DEF", "")

