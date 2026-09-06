import 'package:flutter/material.dart';
import 'package:flutter_sign_keypair/flutter_sign_keypair.dart';

/// A deliberately plain harness for the plugin.
///
/// Its job is to make the two facts that matter visible on a real device: which
/// backing the platform actually gave us, and what a signature costs. It is not
/// a design showcase.
void main() => runApp(const ExampleApp());

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) =>
      const MaterialApp(title: 'flutter_sign_keypair', home: SignerDemoPage());
}

class SignerDemoPage extends StatefulWidget {
  const SignerDemoPage({super.key});

  @override
  State<SignerDemoPage> createState() => _SignerDemoPageState();
}

class _SignerDemoPageState extends State<SignerDemoPage> {
  final SignKeypair _signer = SignKeypair();
  final List<String> _log = <String>[];
  bool _busy = false;

  void _append(String line) => setState(() => _log.insert(0, line));

  Future<void> _run(String label, Future<String> Function() action) async {
    setState(() => _busy = true);
    try {
      _append('$label: ${await action()}');
    } on SecureSignerException catch (e) {
      _append('$label failed [${e.code}]: ${e.message}');
    } finally {
      setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('flutter_sign_keypair')),
      body: Column(
        children: <Widget>[
          Wrap(
            spacing: 8,
            children: <Widget>[
              FilledButton(
                onPressed: _busy
                    ? null
                    : () => _run(
                        'capabilities',
                        () async => (await _signer.capabilities()).toString(),
                      ),
                child: const Text('Capabilities'),
              ),
              FilledButton(
                onPressed: _busy
                    ? null
                    : () => _run('generateKey', () async {
                        final SecureKey key = await _signer.generateKey(
                          overwrite: true,
                        );
                        return '${key.backing.name} '
                            '(hardwareBacked=${key.isHardwareBacked}) '
                            'x=${key.publicKey.x}';
                      }),
                child: const Text('Generate key'),
              ),
              FilledButton(
                onPressed: _busy
                    ? null
                    : () => _run(
                        'signCompactJws',
                        () => _signer.signCompactJws(
                          payload: <String, dynamic>{
                            'timestamp_ms':
                                DateTime.now().millisecondsSinceEpoch,
                            'device_id': 'demo-device',
                            'method': 'GET',
                            'path': '/bff/v1/accounts/balance',
                          },
                        ),
                      ),
                child: const Text('Sign'),
              ),
              FilledButton(
                onPressed: _busy
                    ? null
                    : () => _run('deleteKey', () async {
                        await _signer.deleteKey();
                        return 'deleted';
                      }),
                child: const Text('Delete key'),
              ),
            ],
          ),
          const Divider(),
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.all(12),
              itemCount: _log.length,
              itemBuilder: (BuildContext context, int index) => Padding(
                padding: const EdgeInsets.symmetric(vertical: 4),
                child: SelectableText(
                  _log[index],
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
