import unittest
from unittest.mock import Mock

from wristband.django_auth.decorators import wristband_auth_required


class TestWristbandAuthRequiredDecorator(unittest.TestCase):
    """Test cases for the wristband_auth_required decorator."""

    def test_decorator_sets_attribute(self):
        """Test that decorator sets wristband_auth_required attribute to True."""

        @wristband_auth_required
        def dummy_view(request):
            return "test"

        self.assertTrue(hasattr(dummy_view, "wristband_auth_required"))
        self.assertEqual(dummy_view.wristband_auth_required, True)

    def test_decorator_returns_original_function(self):
        """Test that decorator returns the original function unchanged."""

        def original_view(request):
            return "original"

        decorated_view = wristband_auth_required(original_view)

        # Should be the same function object
        self.assertIs(decorated_view, original_view)

    def test_decorated_function_works_normally(self):
        """Test that decorated function still works as expected."""

        @wristband_auth_required
        def test_view(request):
            return "Hello World"

        mock_request = Mock()
        response = test_view(mock_request)

        self.assertEqual(response, "Hello World")

    def test_function_name_preserved(self):
        """Test that the original function name is preserved."""

        @wristband_auth_required
        def my_special_view(request):
            return "test"

        self.assertEqual(my_special_view.__name__, "my_special_view")

    def test_function_docstring_preserved(self):
        """Test that the original function docstring is preserved."""

        @wristband_auth_required
        def documented_view(request):
            """This is a test view with documentation."""
            return "test"

        self.assertEqual(documented_view.__doc__, "This is a test view with documentation.")

    def test_function_with_args_and_kwargs(self):
        """Test that decorated function works with various arguments."""

        @wristband_auth_required
        def view_with_args(request, arg1, arg2=None, *args, **kwargs):
            return f"arg1: {arg1}, arg2: {arg2}"

        mock_request = Mock()
        response = view_with_args(mock_request, "test1", arg2="test2")

        self.assertEqual(response, "arg1: test1, arg2: test2")
        # Check attribute is still set
        self.assertTrue(view_with_args.wristband_auth_required)

    def test_multiple_decorations(self):
        """Test that function can be decorated multiple times without issues."""

        def other_decorator(func):
            func.other_attribute = "test"
            return func

        @other_decorator
        @wristband_auth_required
        def multi_decorated_view(request):
            return "test"

        # Both attributes should be present
        self.assertTrue(multi_decorated_view.wristband_auth_required)
        self.assertEqual(multi_decorated_view.other_attribute, "test")

    def test_decorator_with_lambda(self):
        """Test that decorator works with lambda functions."""
        decorated_lambda = wristband_auth_required(lambda request: "lambda")

        self.assertTrue(decorated_lambda.wristband_auth_required)

        mock_request = Mock()
        response = decorated_lambda(mock_request)
        self.assertEqual(response, "lambda")

    def test_attribute_type_is_boolean(self):
        """Test that the attribute is specifically boolean True."""

        @wristband_auth_required
        def test_view(request):
            return "test"

        self.assertIsInstance(test_view.wristband_auth_required, bool)
        self.assertIs(test_view.wristband_auth_required, True)

    def test_decorator_is_idempotent(self):
        """Test that applying decorator multiple times doesn't break anything."""

        def original_view(request):
            return "test"

        # Apply decorator twice
        once_decorated = wristband_auth_required(original_view)
        twice_decorated = wristband_auth_required(once_decorated)

        # Should still work and have the attribute
        self.assertTrue(twice_decorated.wristband_auth_required)
        self.assertIs(twice_decorated, original_view)  # Still same function object

    def test_no_side_effects_on_undecorated_functions(self):
        """Test that undecorated functions don't have the attribute."""

        def undecorated_view(request):
            return "test"

        self.assertFalse(hasattr(undecorated_view, "wristband_auth_required"))

    def test_function_signature_unchanged(self):
        """Test that the function signature is not altered."""

        def original_view(request, pk, slug=None):
            return f"pk: {pk}, slug: {slug}"

        decorated_view = wristband_auth_required(original_view)

        # Check that we can still call with same signature
        mock_request = Mock()
        result = decorated_view(mock_request, "123", slug="test-slug")
        self.assertEqual(result, "pk: 123, slug: test-slug")

    def test_function_exceptions_preserved(self):
        """Test that exceptions from the original function are preserved."""

        @wristband_auth_required
        def error_view(request):
            raise ValueError("Test error")

        mock_request = Mock()
        with self.assertRaises(ValueError) as cm:
            error_view(mock_request)

        self.assertEqual(str(cm.exception), "Test error")
        # Attribute should still be set
        self.assertTrue(error_view.wristband_auth_required)

    def test_function_return_values_preserved(self):
        """Test that various return types are preserved."""
        test_cases = [
            ("string", "string"),
            (42, 42),
            ([1, 2, 3], [1, 2, 3]),
            ({"key": "value"}, {"key": "value"}),
            (None, None),
        ]

        for expected_return, test_input in test_cases:
            with self.subTest(return_value=expected_return):

                @wristband_auth_required
                def test_view(request):
                    return test_input

                mock_request = Mock()
                result = test_view(mock_request)
                self.assertEqual(result, expected_return)
                self.assertTrue(test_view.wristband_auth_required)


if __name__ == "__main__":
    unittest.main()
