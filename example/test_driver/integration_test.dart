import 'package:integration_test/integration_test_driver.dart';

/// Driver for `flutter drive`, which — unlike `flutter test integration_test/` —
/// accepts `--profile`. Benchmark numbers from a debug build are meaningless
/// (Dart runs unoptimised in the VM), so the benchmark must be driven this way.
Future<void> main() => integrationDriver();
