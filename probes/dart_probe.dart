import 'dart:async';
import 'dart:convert';
import 'dart:io';

Future<void> main(List<String> args) async {
  final duration = Duration(milliseconds: (double.parse(args[1]) * 1000).round());
  final client = HttpClient()..connectionTimeout = duration;
  void emit(String state, String detail) => print('EMUDHRA_JSON:${jsonEncode({'state': state, 'detail': detail})}');
  try {
    final request = await client.getUrl(Uri.parse(args[0])).timeout(duration);
    request.followRedirects = false;
    final response = await request.close().timeout(duration);
    emit('accepted', 'HTTP ${response.statusCode}');
  } catch (error) {
    emit('error', error.toString());
  } finally { client.close(force: true); }
}
