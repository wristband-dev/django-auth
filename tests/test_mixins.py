import unittest
from unittest.mock import Mock

from wristband.django_auth.mixins import WristbandAuthRequiredMixin


class TestWristbandAuthRequiredMixin(unittest.TestCase):
    """Test cases for the WristbandAuthRequiredMixin."""

    def test_mixin_is_class(self):
        """Test that WristbandAuthRequiredMixin is a class."""
        self.assertTrue(isinstance(WristbandAuthRequiredMixin, type))

    def test_mixin_can_be_inherited(self):
        """Test that the mixin can be inherited by other classes."""

        class TestView(WristbandAuthRequiredMixin):
            def get(self, request):
                return "test response"

        # Should be able to create instance
        view = TestView()
        self.assertIsInstance(view, WristbandAuthRequiredMixin)
        self.assertIsInstance(view, TestView)

    def test_mixin_in_inheritance_hierarchy(self):
        """Test that mixin appears in the method resolution order."""

        class MockView:
            def dispatch(self, request):
                return "dispatched"

        class TestView(WristbandAuthRequiredMixin, MockView):
            pass

        TestView()

        # Check inheritance hierarchy
        self.assertTrue(issubclass(TestView, WristbandAuthRequiredMixin))
        self.assertTrue(issubclass(TestView, MockView))
        self.assertIn(WristbandAuthRequiredMixin, TestView.__mro__)

    def test_mixin_inheritance_order_matters(self):
        """Test different inheritance orders work correctly."""

        class BaseView:
            def method(self):
                return "base"

        # Mixin first
        class TestView1(WristbandAuthRequiredMixin, BaseView):
            pass

        # Mixin second
        class TestView2(BaseView, WristbandAuthRequiredMixin):
            pass

        view1 = TestView1()
        view2 = TestView2()

        # Both should be instances of the mixin
        self.assertIsInstance(view1, WristbandAuthRequiredMixin)
        self.assertIsInstance(view2, WristbandAuthRequiredMixin)

        # Both should inherit base functionality
        self.assertEqual(view1.method(), "base")
        self.assertEqual(view2.method(), "base")

    def test_mixin_with_multiple_inheritance(self):
        """Test mixin works with multiple inheritance scenarios."""

        class FirstMixin:
            first_attr = "first"

        class SecondMixin:
            second_attr = "second"

        class TestView(WristbandAuthRequiredMixin, FirstMixin, SecondMixin):
            view_attr = "view"

        view = TestView()

        # Should have all attributes
        self.assertEqual(view.first_attr, "first")
        self.assertEqual(view.second_attr, "second")
        self.assertEqual(view.view_attr, "view")

        # Should be instance of all mixins
        self.assertIsInstance(view, WristbandAuthRequiredMixin)
        self.assertIsInstance(view, FirstMixin)
        self.assertIsInstance(view, SecondMixin)

    def test_mixin_doesnt_override_methods(self):
        """Test that empty mixin doesn't interfere with method calls."""

        class BaseView:
            def get(self, request):
                return "get response"

            def post(self, request):
                return "post response"

        class TestView(WristbandAuthRequiredMixin, BaseView):
            pass

        view = TestView()
        mock_request = Mock()

        # Methods should work normally
        self.assertEqual(view.get(mock_request), "get response")
        self.assertEqual(view.post(mock_request), "post response")

    def test_mixin_can_be_detected_with_isinstance(self):
        """Test that isinstance works for detecting the mixin."""

        class TestView(WristbandAuthRequiredMixin):
            pass

        class OtherView:
            pass

        test_view = TestView()
        other_view = OtherView()

        # isinstance should work
        self.assertTrue(isinstance(test_view, WristbandAuthRequiredMixin))
        self.assertFalse(isinstance(other_view, WristbandAuthRequiredMixin))

    def test_mixin_can_be_detected_with_issubclass(self):
        """Test that issubclass works for detecting the mixin."""

        class TestView(WristbandAuthRequiredMixin):
            pass

        class OtherView:
            pass

        # issubclass should work
        self.assertTrue(issubclass(TestView, WristbandAuthRequiredMixin))
        self.assertFalse(issubclass(OtherView, WristbandAuthRequiredMixin))

    def test_mixin_in_method_resolution_order(self):
        """Test that mixin appears in MRO for inheritance checking."""

        class BaseView:
            pass

        class TestView(WristbandAuthRequiredMixin, BaseView):
            pass

        # Should appear in MRO
        mro = TestView.__mro__
        self.assertIn(WristbandAuthRequiredMixin, mro)
        self.assertIn(BaseView, mro)
        self.assertIn(object, mro)  # All classes inherit from object

    def test_mixin_with_custom_methods(self):
        """Test mixin with views that have custom methods."""

        class TestView(WristbandAuthRequiredMixin):
            def custom_method(self):
                return "custom"

            def get_context_data(self):
                return {"test": "data"}

        view = TestView()

        # Custom methods should work
        self.assertEqual(view.custom_method(), "custom")
        self.assertEqual(view.get_context_data(), {"test": "data"})

        # Still should be instance of mixin
        self.assertIsInstance(view, WristbandAuthRequiredMixin)

    def test_multiple_views_with_mixin(self):
        """Test that multiple different views can use the same mixin."""

        class ListView(WristbandAuthRequiredMixin):
            def get(self, request):
                return "list view"

        class DetailView(WristbandAuthRequiredMixin):
            def get(self, request, pk):
                return f"detail view {pk}"

        list_view = ListView()
        detail_view = DetailView()

        # Both should be instances of the mixin
        self.assertIsInstance(list_view, WristbandAuthRequiredMixin)
        self.assertIsInstance(detail_view, WristbandAuthRequiredMixin)

        # Both should work independently
        mock_request = Mock()
        self.assertEqual(list_view.get(mock_request), "list view")
        self.assertEqual(detail_view.get(mock_request, "123"), "detail view 123")

    def test_mixin_class_attributes(self):
        """Test that class attributes work normally with the mixin."""

        class TestView(WristbandAuthRequiredMixin):
            template_name = "test.html"
            context_object_name = "object"

        view = TestView()

        # Class attributes should be accessible
        self.assertEqual(view.template_name, "test.html")
        self.assertEqual(view.context_object_name, "object")
        self.assertEqual(TestView.template_name, "test.html")

    def test_mixin_with_init_method(self):
        """Test mixin works with classes that have __init__ methods."""

        class TestView(WristbandAuthRequiredMixin):
            def __init__(self, custom_arg):
                self.custom_arg = custom_arg

        view = TestView("test_value")

        # Should initialize correctly
        self.assertEqual(view.custom_arg, "test_value")
        self.assertIsInstance(view, WristbandAuthRequiredMixin)

    def test_empty_mixin_has_no_methods(self):
        """Test that the empty mixin doesn't add any methods."""
        # Get methods from the mixin (excluding special methods)
        mixin_methods = [method for method in dir(WristbandAuthRequiredMixin) if not method.startswith("__")]

        # Should be empty (no methods defined)
        self.assertEqual(len(mixin_methods), 0)

    def test_mixin_str_and_repr(self):
        """Test that string representations work with the mixin."""

        class TestView(WristbandAuthRequiredMixin):
            def __str__(self):
                return "TestView instance"

        view = TestView()

        # String representation should work
        self.assertEqual(str(view), "TestView instance")

        # Class representation should include mixin
        class_repr = repr(TestView)
        self.assertIn("WristbandAuthRequiredMixin", class_repr)


if __name__ == "__main__":
    unittest.main()
