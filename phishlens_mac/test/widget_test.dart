import 'package:flutter_test/flutter_test.dart';
import 'package:phishlens_mac/main.dart';

void main() {
  testWidgets('PhishLens macOS app renders header and controls', (WidgetTester tester) async {
    await tester.pumpWidget(const PhishLensMacApp());
    expect(find.text('PhishLens macOS'), findsOneWidget);
    expect(find.text('Scan & Check Link'), findsOneWidget);
  });
}
