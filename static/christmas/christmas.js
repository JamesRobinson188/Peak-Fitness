const canvas = document.getElementById('snow-canvas');
const ctx = canvas.getContext('2d');

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

const snowflakes = [];

function createSnowflake() {
    return {
        x: Math.random() * canvas.width, // X position
        y: Math.random() * canvas.height, // Y position
        radius: Math.random() * 3 + 1, // Snowflake size
        opacity: Math.random() * 0.7 + 0.3, // Transparency
        speedY: Math.random() * 1 + 0.5, // Vertical speed
        speedX: (Math.random() - 0.5) * 0.5 // Horizontal drift
    };
}

function initSnowflakes() {
    const numSnowflakes = Math.min(Math.floor(canvas.width / 10), 200);
    for (let i = 0; i < numSnowflakes; i++) {
        snowflakes.push(createSnowflake());
    }
}

function updateSnowflakes() {
    for (const flake of snowflakes) {
        flake.y += flake.speedY;
        flake.x += flake.speedX;

        if (flake.y > canvas.height) {
            flake.y = -flake.radius;
            flake.x = Math.random() * canvas.width;
        }

        if (flake.x > canvas.width || flake.x < 0) {
            flake.x = Math.random() * canvas.width;
        }
    }
}

function drawSnowflakes() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const flake of snowflakes) {
        ctx.beginPath();
        ctx.arc(flake.x, flake.y, flake.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255, 255, 255, ${flake.opacity})`;
        ctx.fill();
    }
}

function animate() {
    updateSnowflakes();
    drawSnowflakes();
    requestAnimationFrame(animate);
}

window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    snowflakes.length = 0; // Clear existing snowflakes
    initSnowflakes();
});

initSnowflakes();
animate();

// INSTRUCTIONS

// ADD THE FOLLOWING TO base.html

// STYLING AT THE TOP BENEATH HEAD
// <style>
//     canvas {
//         position: fixed;
//         top: 0;
//         left: 0;
//         width: 100%;
//         height: 100%;
//         pointer-events: none;
//         z-index: 9999;
//     }
// </style>

// SCRIPT AT THE BOTTOM BEFORE THE CLOSING BODY TAG
// <script src="/static/christmas.js"></script>

// ADD THE CANVAS DIRECTLY BELOW THE BODY TAG
// <canvas id="snow-canvas"></canvas>
