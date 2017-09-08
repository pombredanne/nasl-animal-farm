"""
Unit tests for plugin files object
"""

import pytest

from lib.file.plugin import Plugin

class TestPlugins:
    """
    Pytest Class that contains unit tests for the Plugins class
    """

    def test_plugin_creation_nasl(self):
        """
        Tests happy path Plugin creation for a .nasl
        """
        testname = 'plugin.nasl'
        plugin = Plugin(testname)
        assert plugin.get_plugin_name() == testname, "Create of a Plugin object for a .nasl failed"
        assert plugin.parsed == False, "Plugin has been parsed too early."


    def test_plugin_creation_inc(self):
        """
        Tests happy path Plugin creation for a .inc
        """
        testname = 'plugin.inc'
        plugin = Plugin(testname)
        assert plugin.get_plugin_name() == testname, "Create of a Plugin object for a .inc failed"
        assert plugin.parsed == False, "Include file has been parsed too early."


    def test_plugin_creation_no_extension(self):
        """
        Tests Plugin creation for a file with no extension
        """
        with pytest.raises(Exception) as exc:
            testname = 'just-a-file'
            plugin = Plugin(testname)
        assert "Supplied file has the wrong extension" in str(exc)


    def test_parse_plain_function_call(self):
        """
        Verifies that parsing a bare function call will return a result
        """
        lines = ["test_func(args, new_arg, 1);"]
        plugin = Plugin("test.nasl")
        pt = plugin._parse(lines)
        assert len(pt) == 1, "Single function call yielded wrong parse tree."
        assert pt[0][0] == 'FN_CALL', "Single function call yielded wrong first element."
        assert pt[0][1] == 'test_func', "Single function call yielded wrong function name. "
        

    def test_parse_function_call_in_function_call_args(self):
        """
        Verfies that parsing a function call that contains function calls in the
        function arguments returns the correct parse tree.
        """
        lines = ["t_func(t2_func(), arg3);"]
        plugin = Plugin("test.nasl")
        pt = plugin._parse(lines)
        assert len(pt) == 2, "Nested function calls yielded wrong parse tree."
        assert pt[0][0] == 'FN_CALL', "Nested function calls yielded wrong first element."
        assert pt[0][1] == 't2_func', "Nested function calls yielded wrong function name one. "
        assert pt[1][0] == 'FN_CALL', "Nested function calls yielded wrong second element."
        assert pt[1][1] == 't_func', "Nested function calls yielded wrong function name two. "


    def test_parse_function_definition(self):
        """
        Verified that parsing a function definition creates a function scope
        """
        lines = ["function my_func(args, args2) { }"]
        plugin = Plugin("test.nasl")
        pt = plugin._parse(lines)
        assert len(pt) == 1, "Function definition yielded wrong sized parse tree."
        assert pt[0][0] == 'FN_DEF', "Function definition yielded wrong tree element."
        assert pt[0][1] == 'my_func', "Wrong function name stored in parse tree."
        assert len(pt[0][2]) == 0, "Function scope for empty function s.b. 0."


    def test_parse_function_definition_with_func_call(self):
        """
        Verified that parsing a function definition creates a function scope, and
        stores function calls within that scope.
        """
        lines = ["function my_func(args, args2) { ",
                 "val2 = test_func(21); ",
                 "}"]
        plugin = Plugin("test.nasl")
        pt = plugin._parse(lines)
        assert len(pt) == 1, "Function definition yielded wrong sized parse tree."
        assert pt[0][0] == 'FN_DEF', "Function definition yielded wrong tree element."
        assert pt[0][1] == 'my_func', "Wrong function name stored in parse tree."
        assert len(pt[0][2]) == 1, "Function scope for function with 1 call s.b. 1."
        assert pt[0][2][0][0] == 'FN_CALL', "A function call was not stored within the scope."
        assert pt[0][2][0][1] == 'test_func', "The wrong function stored with function scope."


    def test_parse_foreach_with_func_call(self):
        """
        Verified that parsing a foreach with embedded function calls does not register the sequence
        as a function call and does store function calls within the block.
        """
        lines = ["foreach path (paths) { ",
                 "value = go_go_func('party time'); ",
                 "}"]
        plugin = Plugin("test.nasl")
        pt = plugin._parse(lines)
        assert len(pt) == 1, "Wrong number of elements parsing a foreach loop."
        assert pt[0][0] == 'FN_CALL', "Function definition yielded wrong tree element."
        assert pt[0][1] == 'go_go_func', "Wrong function call stored in foreach parse tree."


    def test_parse_foreach_with_func_call_in_if_block(self):
        """
        Verified that parsing a foreach with embedded function calls that is inside an if block
        does not register the sequence as a function call and does store function calls within the block.
        """
        lines = ["if (True) { foreach path (paths) { ",
                 "value = go_go_func('party time'); ",
                 "}}"]
        plugin = Plugin("test.nasl")
        pt = plugin._parse(lines)
        assert len(pt) == 1, "Wrong number of elements parsing a foreach loop."
        assert pt[0][0] == 'FN_CALL', "Function definition yielded wrong tree element."
        assert pt[0][1] == 'go_go_func', "Wrong function call stored in foreach parse tree."


    def test_parse_namespace(self):
        """
        Verify that a namespace is parsed correctly.
        """
        lines = ["namespace funky {}"]
        plugin = Plugin("test.nasl")
        pt = plugin._parse(lines)
        assert len(pt) == 1, "Namespace definition yielded wrong sized parse tree."
        assert pt[0][0] == 'NAMESPACE', "Namespace definition yielded wrong parse element."
        assert pt[0][1] == 'funky', "Wrong namespace name stored in parse tree."


    def test_parse_object(self):
        """
        Verify that a object is parsed correctly.
        """
        lines = ["object nightstand {}"]
        plugin = Plugin("test.nasl")
        pt = plugin._parse(lines)
        assert len(pt) == 1, "Object definition yielded wrong sized parse tree."
        assert pt[0][0] == 'OBJECT', "Object definition yielded wrong parse element."
        assert pt[0][1] == 'nightstand', "Wrong object name stored in parse tree."

    def test_escaped_single_quote(self):
        """
        Verify that an escaped single quote does not enter a quote block.
        """
        lines = ["test_fn('My string arg\\'s daughter.');",
                 'test_fn2();']
        plugin = Plugin("test.nasl")
        pt = plugin._parse(lines)
        assert len(pt) == 2, "The escaped single quote was not ignored."

    def test_escaped_double_quote(self):
        """
        Verify that an escaped double quote does not enter a quote block.
        """
        lines = ["test_fn('My string arg\\\"s daughter.');",
                 'test_fn2();']
        plugin = Plugin("test.nasl")
        pt = plugin._parse(lines)
        assert len(pt) == 2, "The escaped double quote was not ignored."

    def test_double_quote_in_single_quoted_string(self):
        """
        Verify that a double quote inside a single quote block is not considered.
        """
        lines = ['test_fn("My string arg' + "'" + 'is cool.");',
                 'test_fn2();']
        plugin = Plugin("test.nasl")
        pt = plugin._parse(lines)
        assert len(pt) == 2, "The encapsulated single quote was not ignored."

    def test_single_quote_in_double_quoted_string(self):
        """
        Verify that a single quote inside a double quote block is not considered.
        """
        lines = ["test_fn('My string arg" + '"' + "is cool.');",
                 'test_fn2();']
        plugin = Plugin("test.nasl")
        pt = plugin._parse(lines)
        assert len(pt) == 2, "The encapsulated double quote was not ignored."

    def test_dict_def_does_not_pollute_fn_call(self):
        """
        Verify that a dict declaration in a namespace doesn't change the name of the source
        function of a function call that follows it.
        """
        lines = ["namespace collib {",
                 "global_var __acc_table = {'data':'', 'int':0, 'list':make_list(), 'set':make_set() };",
                 "function make_set() {",
                 "return new ('collib::set', _FCT_ANON_ARGS);}",
                 "}"]
        plugin = Plugin("test.nasl")
        pt = plugin._parse(lines)
        assert pt[0][1] == "collib", "The namespace was wrong."
        assert pt[0][2][2][1] == "make_set", "The function def was polluted."
        assert pt[0][2][2][2][0][1] == "new", "The function call was polluted."


    def test_dict_def_after_fn_def_parses(self):
        """
        Verify that a dict declaration after a function definition within scope is parsed without errors
        """
        lines = ["namespace vcf{",
                 "function dbg() {",
                 "display('stuff\\n');}",
                 "global_var __acc_table = {'data':'', 'int':0, 'list':make_list(), 'set':make_set() };",
                 "}"]
        plugin = Plugin("test.nasl")
        pt = plugin._parse(lines)
        assert pt[0][1] == "vcf", "The namespace was wrong."
        assert pt[0][2][0][1] == "dbg", "The function def was polluted."
        assert pt[0][2][0][2][0][1] == "display", "The function call was polluted."

