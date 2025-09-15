import unittest
from unittest.mock import Mock, patch

from wristband.django_auth.decorators import wristband_auth_required
from wristband.django_auth.mixins import WristbandAuthRequiredMixin
from wristband.django_auth.utils import is_wristband_auth_required


class TestIsWristbandAuthRequired(unittest.TestCase):
    """Test cases for the is_wristband_auth_required function."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_request = Mock()
        self.mock_request.path = "/test-path/"

    @patch("wristband.django_auth.utils.resolve")
    def test_returns_true_for_decorated_function_view(self, mock_resolve):
        """Test that it returns True for function views with @wristband_auth_required decorator."""

        @wristband_auth_required
        def test_view(request):
            return "response"

        mock_resolver_match = Mock(spec=["func"])
        mock_resolver_match.func = test_view
        mock_resolve.return_value = mock_resolver_match

        result = is_wristband_auth_required(self.mock_request)

        self.assertTrue(result)
        mock_resolve.assert_called_once_with("/test-path/")

    @patch("wristband.django_auth.utils.resolve")
    def test_returns_false_for_undecorated_function_view(self, mock_resolve):
        """Test that it returns False for function views without decorator."""

        def test_view(request):
            return "response"

        mock_resolver_match = Mock(spec=["func"])
        mock_resolver_match.func = test_view
        mock_resolve.return_value = mock_resolver_match

        result = is_wristband_auth_required(self.mock_request)

        self.assertFalse(result)

    @patch("wristband.django_auth.utils.resolve")
    def test_returns_true_for_class_view_with_mixin(self, mock_resolve):
        """Test that it returns True for class-based views with WristbandAuthRequiredMixin."""

        class TestView(WristbandAuthRequiredMixin):
            def get(self, request):
                return "response"

        mock_view_func = Mock(spec=["view_class"])
        mock_view_func.view_class = TestView

        mock_resolver_match = Mock(spec=["func"])
        mock_resolver_match.func = mock_view_func
        mock_resolve.return_value = mock_resolver_match

        result = is_wristband_auth_required(self.mock_request)

        self.assertTrue(result)

    @patch("wristband.django_auth.utils.resolve")
    def test_returns_false_for_class_view_without_mixin(self, mock_resolve):
        """Test that it returns False for class-based views without the mixin."""

        class TestView:
            def get(self, request):
                return "response"

        mock_view_func = Mock(spec=["view_class"])
        mock_view_func.view_class = TestView

        mock_resolver_match = Mock(spec=["func"])
        mock_resolver_match.func = mock_view_func
        mock_resolve.return_value = mock_resolver_match

        result = is_wristband_auth_required(self.mock_request)

        self.assertFalse(result)

    @patch("wristband.django_auth.utils.resolve")
    def test_returns_false_when_exception_occurs(self, mock_resolve):
        """Test that it returns False when any exception occurs."""
        mock_resolve.side_effect = Exception("Generic error")

        result = is_wristband_auth_required(self.mock_request)

        self.assertFalse(result)

    @patch("wristband.django_auth.utils.resolve")
    def test_handles_missing_view_class_attribute(self, mock_resolve):
        """Test that it handles missing view_class attribute gracefully."""
        mock_view_func = Mock(spec=[])

        mock_resolver_match = Mock(spec=["func"])
        mock_resolver_match.func = mock_view_func
        mock_resolve.return_value = mock_resolver_match

        result = is_wristband_auth_required(self.mock_request)

        self.assertFalse(result)

    @patch("wristband.django_auth.utils.resolve")
    def test_mixin_inheritance_detection(self, mock_resolve):
        """Test that mixin detection works with inheritance hierarchy."""

        class BaseView(WristbandAuthRequiredMixin):
            pass

        class DerivedView(BaseView):
            def get(self, request):
                return "response"

        mock_view_func = Mock(spec=["view_class"])
        mock_view_func.view_class = DerivedView

        mock_resolver_match = Mock(spec=["func"])
        mock_resolver_match.func = mock_view_func
        mock_resolve.return_value = mock_resolver_match

        result = is_wristband_auth_required(self.mock_request)

        self.assertTrue(result)

    @patch("wristband.django_auth.utils.resolve")
    def test_different_request_paths(self, mock_resolve):
        """Test function works with different request paths."""

        @wristband_auth_required
        def test_view(request):
            return "response"

        mock_resolver_match = Mock(spec=["func"])
        mock_resolver_match.func = test_view
        mock_resolve.return_value = mock_resolver_match

        test_paths = ["/api/test/", "/admin/users/", "/app/dashboard/", "/"]

        for path in test_paths:
            with self.subTest(path=path):
                self.mock_request.path = path
                result = is_wristband_auth_required(self.mock_request)
                self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
