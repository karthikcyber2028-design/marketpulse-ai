from flask import Flask, render_template, request, jsonify, send_from_directory
app = Flask(__name__)

# Sample music library (replace with real MP3 paths)
SONGS = [
    {"id": 1, "title": "Naatu Naatu", "artist": "Rahul Sipligunj", "album": "RRR", "category": "Telugu", "file": "naatu_naalu.mp3"},
    {"id": 2, "title": "Tamil Song 1", "artist": "Artist A", "album": "Album X", "category": "Tamil", "file": "tamil1.mp3"},
    {"id": 3, "title": "Hindi Hit", "artist": "Singer B", "album": "Album Y", "category": "Hindi", "file": "hindi1.mp3"},
    {"id": 4, "title": "English Pop", "artist": "Artist C", "album": "Album Z", "category": "English", "file": "english1.mp3"},
]

@app.route('/')
def home():
    return render_template('index.html', songs=SONGS)

@app.route('/search')
def search():
    q = request.args.get('q', '').lower()
    results = [s for s in SONGS if q in s['title'].lower() or q in s['artist'].lower() or q in s['category'].lower()]
    return jsonify(results)

@app.route('/player/<int:song_id>')
def player(song_id):
    song = next((s for s in SONGS if s['id'] == song_id), None)
    if song:
        return jsonify(song)
    return jsonify({'error': 'not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)