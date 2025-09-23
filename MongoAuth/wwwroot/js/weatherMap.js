var map;
var markers = [];

function initWeatherMap() {
    if (map) return; // prevent multiple init
    map = L.map('weatherMap').setView([20, 77], 5);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; OpenStreetMap contributors'
    }).addTo(map);
    console.log("✅ Map initialized");
}

function updateWeatherMap(data) {
    try {
        if (!map) {
            console.warn("Map not initialized");
            return;
        }

        console.log("📌 Data received in JS:", data);

        // Remove old markers
        markers.forEach(m => map.removeLayer(m));
        markers = [];

        if (!data || !Array.isArray(data) || data.length === 0) {
            console.warn("⚠️ No locations to display");
            return;
        }

        data.forEach(loc => {
            if (!loc || loc.latitude == null || loc.longitude == null) return;

            let marker = L.marker([loc.latitude, loc.longitude])
                .addTo(map)
                .bindPopup(`<b>${loc.city}, ${loc.state}</b><br/>Weather: ${loc.weather}`);

            markers.push(marker);
            console.log("✅ Marker added:", loc.city, loc.latitude, loc.longitude);
        });

        // Adjust map to fit all markers
        if (markers.length === 1) {
            // If only one marker → center map directly
            map.setView(markers[0].getLatLng(), 10); // you can adjust zoom level (e.g., 12–14 for city view)
        } else if (markers.length > 1) {
            // Fit all markers
            let group = L.featureGroup(markers);
            map.fitBounds(group.getBounds().pad(0.2));
        }


    } catch (err) {
        console.error("❌ Error in updateWeatherMap:", err);
    }
}
