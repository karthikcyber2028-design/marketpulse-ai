document.addEventListener('DOMContentLoaded', () => {
    const songs = window.SONGS || [];

    const songGrid = document.getElementById('songGrid');
    const player = document.getElementById('player');
    const currentTitle = document.getElementById('currentTitle');
    const currentArtist = document.getElementById('currentArtist');
    const playBtn = document.getElementById('playBtn');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const volumeSlider = document.getElementById('volumeSlider');
    const progress = document.getElementById('progress');
    const currentTimeEl = document.getElementById('currentTime');
    const durationEl = document.getElementById('duration');
    const searchInput = document.getElementById('searchInput');
    const catBtns = document.querySelectorAll('.cat-btn');

    let currentIdx = -1;
    let isPlaying = false;

    // Render song cards with click to play
    function renderSongs(filter = 'all') {
        songGrid.innerHTML = '';
        const filtered = filter === 'all'
            ? songs
            : songs.filter(s => s.category === filter);
        filtered.forEach((s, i) => {
            const div = document.createElement('div');
            div.className = 'song-card';
            div.dataset.id = s.id;
            div.textContent = `${s.title} - ${s.artist}`;
            div.addEventListener('click', () => playSong(i));
            songGrid.appendChild(div);
        });
    }

    function playSong(idx) {
        if (idx < 0 || idx >= songs.length) return;
        currentIdx = idx;
        const s = songs[idx];
        currentTitle.textContent = s.title;
        currentArtist.textContent = s.artist;
        playBtn.textContent = '⏸️';
        isPlaying = true;
        updateActiveSong();
    }

    function updateActiveSong() {
        document.querySelectorAll('.song-card').forEach(c => c.classList.toggle('active', parseInt(c.dataset.id) === songs[currentIdx].id);
    }

    // Play / Pause
    playBtn.addEventListener('click', () => {
        isPlaying = !isPlaying;
        playBtn.textContent = isPlaying ? '⏸️' : '▶️';
    });

    // Prev / Next
    prevBtn.addEventListener('click', () => { if (currentIdx > 0) playSong(currentIdx - 1); });
    nextBtn.addEventListener('click', () => { if (currentIdx < songs.length - 1) playSong(currentIdx + 1); });

    // Volume control
    volumeSlider.addEventListener('input', e => { /* audio.volume = e.target.value; */ });

    // Progress bar (mock)
    function updateProgress() { /* placeholder */ }

    // Category filter
    catBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            catBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderSongs(btn.dataset.category);
        });
    });

    // Search filter
    searchInput.addEventListener('input', e => {
        const term = e.target.value.toLowerCase();
        document.querySelectorAll('.song-card').forEach(card => {
            const title = card.textContent.toLowerCase();
            card.style.display = title.includes(term) ? '' : 'none';
        });
    });

    // Initial render
    renderSongs();
});