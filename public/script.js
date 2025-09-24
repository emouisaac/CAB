// Helper: Get query param
function getQueryParam(name) {
    const url = new URL(window.location.href);
    return url.searchParams.get(name);
}

// On every page load, check backend for logged-in user (Google or local)
document.addEventListener('DOMContentLoaded', function() {
    fetch('/auth/user', { credentials: 'include' })
        .then(res => res.json())
        .then(user => {
            if (user && user.displayName) {
                loginBtn.style.display = 'none';
                profileNameContainer.style.display = 'block';
                profileNameContainer.innerHTML = `<a href="#" id="logout-btn">${user.displayName}</a>`;
            } else {
                loginBtn.style.display = 'inline-block';
                profileNameContainer.style.display = 'none';
            }
        })
        .catch(() => {
            loginBtn.style.display = 'inline-block';
            profileNameContainer.style.display = 'none';
        });
});
const pages = document.querySelectorAll('.page');
// Initialize AOS
AOS.init();

const navLinks = document.querySelectorAll('.nav-link');
const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
const closeMenuBtn = document.querySelector('.close-menu-btn');
const nav = document.querySelector('nav');
const themeToggle = document.querySelector('.theme-toggle');
const loginBtn = document.getElementById('login-btn');
const loginModal = document.getElementById('loginModal');
const closeLoginModal = document.getElementById('close-login-modal');
const modalClose = document.querySelector('.modal-close');
const loginForm = document.getElementById('loginForm');
const profileNameContainer = document.getElementById('profile-name-container');
const affiliateName = document.getElementById('affiliate-name');
const affiliateEmail = document.getElementById('affiliate-email');
const affiliateUsername = document.getElementById('affiliate-username');
const sendCodeBtn = document.getElementById('send-code-btn');
const loginCodeBtn = document.getElementById('login-code-btn');
const codeGroup = document.getElementById('code-group');
const googleLoginBtn = document.getElementById('google-login-btn');
const copyReferralBtn = document.getElementById('copy-referral-btn');
const referralCodeText = document.getElementById('referral-code-text');
const contactForm = document.getElementById('contactForm');
let sentCode = '';

// Navigation Functions
function showPage(pageId) {
    pages.forEach(page => {
        page.classList.remove('active');
    });
    document.getElementById(`${pageId}-page`).classList.add('active');
    
    // Update active nav link
    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('data-page') === pageId) {
            link.classList.add('active');
        }
    });
    
    // Close mobile menu if open
    if (nav.classList.contains('active')) {
        nav.classList.remove('active');
        closeMenuBtn.style.display = 'none';
        mobileMenuBtn.style.display = 'block';
    }
    
    // Scroll to top
    window.scrollTo(0, 0);
}



// Event Listeners for Navigation
navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const pageId = link.getAttribute('data-page');
        showPage(pageId);
    });
});

// Mobile Menu Toggle
mobileMenuBtn.addEventListener('click', () => {
    nav.classList.add('active');
    mobileMenuBtn.style.display = 'none';
    closeMenuBtn.style.display = 'block';
});

closeMenuBtn.addEventListener('click', () => {
    nav.classList.remove('active');
    closeMenuBtn.style.display = 'none';
    mobileMenuBtn.style.display = 'block';
});

// Theme Toggle
themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('dark-mode');
    if (document.body.classList.contains('dark-mode')) {
        themeToggle.textContent = '☀️';
        localStorage.setItem('theme', 'dark');
    } else {
        themeToggle.textContent = '🌙';
        localStorage.setItem('theme', 'light');
    }
});

// Check for saved theme preference
const savedTheme = localStorage.getItem('theme');
if (savedTheme === 'dark') {
    document.body.classList.add('dark-mode');
    themeToggle.textContent = '☀️';
}

// Login Modal Functions
loginBtn.addEventListener('click', (e) => {
    e.preventDefault();
    loginModal.style.display = 'flex';
});

closeLoginModal.addEventListener('click', () => {
    loginModal.style.display = 'none';
});

modalClose.addEventListener('click', () => {
    loginModal.style.display = 'none';
});



// Login Code Send and Verification (production)
sendCodeBtn.addEventListener('click', async () => {
    const email = document.getElementById('login-email').value;
    if (!email) {
        alert('Please enter your email.');
        return;
    }
    sendCodeBtn.disabled = true;
    sendCodeBtn.textContent = 'Sending...';
    try {
        const res = await fetch('/auth/send-code', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await res.json();
        if (res.ok) {
            alert('A login code has been sent to your email.');
            if (codeGroup) codeGroup.style.display = 'block';
            sendCodeBtn.style.display = 'none';
            loginCodeBtn.style.display = 'inline-block';
        } else {
            alert(data.message || 'Failed to send code.');
        }
    } catch (err) {
        alert('Network error.');
    }
    sendCodeBtn.disabled = false;
    sendCodeBtn.textContent = 'Send Code';
});

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const code = document.getElementById('login-code').value;
    if (!email || !code) {
        alert('Please enter your email and code.');
        return;
    }
    loginCodeBtn.disabled = true;
    loginCodeBtn.textContent = 'Verifying...';
    try {
        const res = await fetch('/auth/verify-code', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, code })
        });
        const data = await res.json();
        if (res.ok) {
            // Success: update UI
            loginBtn.style.display = 'none';
            profileNameContainer.style.display = 'block';
            profileNameContainer.innerHTML = `<a href="#" id="logout-btn">${data.user.username}</a>`;
            loginModal.style.display = 'none';
            if (codeGroup) codeGroup.style.display = 'none';
            sendCodeBtn.style.display = 'inline-block';
            loginCodeBtn.style.display = 'none';
            loginForm.reset();
        } else {
            alert(data.message || 'Invalid code.');
        }
    } catch (err) {
        alert('Network error.');
    }
    loginCodeBtn.disabled = false;
    loginCodeBtn.textContent = 'Login with Code';
});

googleLoginBtn.addEventListener('click', () => {
    // Redirect to backend for Google OAuth
    window.location.href = '/auth/google';
});




// Hide code group on page load
document.addEventListener('DOMContentLoaded', function() {
    if (codeGroup) codeGroup.style.display = 'none';
    sentCode = '';
});



// Logout functionality
profileNameContainer.addEventListener('click', function(e) {
    if (e.target && e.target.id === 'logout-btn') {
        if (confirm('Do you want to log out?')) {
            // Hide username, show LOGIN button
            profileNameContainer.style.display = 'none';
            loginBtn.style.display = 'inline-block';
            loginBtn.textContent = 'LOG IN';
            sentCode = '';
            localStorage.removeItem('loggedInUser');
        }
    }
});

// Copy Referral Code
copyReferralBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(referralCodeText.textContent)
        .then(() => {
            const originalText = copyReferralBtn.textContent;
            copyReferralBtn.textContent = 'Copied!';
            setTimeout(() => {
                copyReferralBtn.textContent = originalText;
            }, 2000);
        })
        .catch(err => {
            console.error('Failed to copy: ', err);
        });
});


// Registration Form Submission
const registerForm = document.getElementById('registerForm');
const registerFormContainer = document.getElementById('register-form-container');
const loginFormContainer = document.getElementById('login-form-container');
if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('register-name').value;
        const email = document.getElementById('register-email').value;
        const password = document.getElementById('register-password').value;
        const referral = document.getElementById('register-referral').value;
        if (!name || !email || !password) {
            alert('Please fill in all required fields.');
            return;
        }
        const submitBtn = registerForm.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Registering...';
        try {
            const res = await fetch('/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, email, password, referral })
            });
            const data = await res.json();
            if (res.ok) {
                alert('Registration successful! Please log in.');
                // Switch to login modal
                if (registerFormContainer && loginFormContainer) {
                    registerFormContainer.style.display = 'none';
                    loginFormContainer.style.display = '';
                }
                registerForm.reset();
            } else {
                alert(data.message || 'Registration failed.');
            }
        } catch (err) {
            alert('Network error.');
        }
        submitBtn.disabled = false;
        submitBtn.textContent = 'Register';
    });
}

// Contact Form Submission
contactForm.addEventListener('submit', (e) => {
    e.preventDefault();
    alert('Thank you for your message! We will get back to you soon.');
    contactForm.reset();
});

// Course Data
const courses = [
    {
        key: 'starter',
        title: 'STARTER PARK',
        description: 'Unlock your crypto journey with our exclusive Starter Park course! Learn the fundamentals of cryptocurrency, understand blockchain technology, and get secure investing tips & strategies.',
        oldPrice: 100,
        newPrice: 90,
        discount: '10% OFF',
        category: 'Beginner',
        duration: '4h 30m',
        lessons: 12
    },
    {
        key: 'trading',
        title: 'Trading Strategies',
        description: 'Explore proven trading strategies and risk management for crypto success! Step-by-step trading tactics, risk management essentials, and real-world crypto trading examples.',
        oldPrice: 300,
        newPrice: 250,
        discount: '17% OFF',
        category: 'Trading',
        duration: '6h 10m',
        lessons: 18
    },
    {
        key: 'technical',
        title: 'Technical Analysis',
        description: 'Master chart patterns, indicators, and technical tools for crypto trading! In-depth chart pattern analysis, technical indicators and signals, and real-world trading strategies.',
        oldPrice: 400,
        newPrice: 350,
        discount: '12% OFF',
        category: 'Analysis',
        duration: '7h 00m',
        lessons: 20
    },
    {
        key: 'portfolio',
        title: 'Portfolio Management',
        description: 'Master the art of building and managing a high-performing crypto portfolio! Diversification strategies for crypto assets, risk management and rebalancing techniques, and long-term growth planning.',
        oldPrice: 600,
        newPrice: 500,
        discount: '17% OFF',
        category: 'Investment',
        duration: '5h 45m',
        lessons: 15
    },
    {
        key: 'masterclass',
        title: 'Masterclass: Wealth Building',
        description: 'Unlock elite-level strategies and wealth-building secrets with our Masterclass course! Advanced portfolio scaling & management, wealth-building strategies for serious investors, and exclusive insights from top crypto experts.',
        oldPrice: 1200,
        newPrice: 1000,
        discount: '17% OFF',
        category: 'Advanced',
        duration: '10h 00m',
        lessons: 30
    }
];

// Blog Data
const blogs = [
    {
        id: 1,
        title: "Bitcoin Halving 2024: What to Expect",
        excerpt: "Explore the potential impact of the upcoming Bitcoin halving on prices and market dynamics.",
        date: "October 15, 2023",
        category: "Market Analysis"
    },
    {
        id: 2,
        title: "Ethereum 2.0: The Complete Guide",
        excerpt: "Everything you need to know about Ethereum's transition to proof-of-stake consensus.",
        date: "September 28, 2023",
        category: "Technology"
    },
    {
        id: 3,
        title: "5 Common Mistakes New Crypto Traders Make",
        excerpt: "Avoid these pitfalls to improve your trading strategy and protect your investments.",
        date: "September 12, 2023",
        category: "Trading Tips"
    },
    {
        id: 4,
        title: "DeFi Summer 2023: Trends and Opportunities",
        excerpt: "An in-depth look at the latest developments in decentralized finance.",
        date: "August 30, 2023",
        category: "DeFi"
    },
    {
        id: 5,
        title: "Regulatory Landscape for Cryptocurrencies in India",
        excerpt: "Understanding the current and future regulatory environment for crypto in India.",
        date: "August 15, 2023",
        category: "Regulation"
    },
    {
        id: 6,
        title: "The Psychology of Crypto Trading",
        excerpt: "How emotions impact trading decisions and strategies to maintain discipline.",
        date: "July 28, 2023",
        category: "Psychology"
    }
];

// Populate Courses on Homepage
function populateHomeCourses() {
    const container = document.getElementById('courses-container');
    const homeCourses = courses.slice(0, 3); // Show only 3 courses on homepage
    container.innerHTML = homeCourses.map(course => `
        <div class="col-lg-4 col-md-6">
            <div class="course-card" data-aos="fade-up">
                <div class="course-image">
                    <i class="fab fa-bitcoin"></i>
                </div>
                <div class="course-content">
                    <span class="course-category">${course.category}</span>
                    <h3 class="course-title">${course.title}</h3>
                    <p class="course-description">${course.description}</p>
                    <div class="course-meta">
                        <span><i class="far fa-clock"></i> ${course.duration}</span>
                        <span><i class="far fa-play-circle"></i> ${course.lessons}</span>
                    </div>
                    <div class="course-price">
                        <span class="old-price" style="color:#aaa;text-decoration:line-through;font-size:1em;">$${course.oldPrice}</span>
                        <span class="new-price" style="color:#009e3c;font-weight:bold;font-size:1.1em;margin-left:8px;">$${course.newPrice}</span>
                        <span class="discount-badge" style="background:#ffe066;color:#b8860b;border-radius:12px;padding:2px 8px;font-size:0.9em;margin-left:6px;font-weight:600;">${course.discount}</span>
                        <a href="/buy-course.html?course=${course.key}" class="btn btn-primary" style="display:block;margin-top:10px;">Enroll Now</a>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

// Populate All Courses on Courses Page
function populateAllCourses() {
    const container = document.getElementById('all-courses-container');
    container.innerHTML = courses.map(course => `
        <div class="col-lg-4 col-md-6 mb-4">
            <div class="course-card" data-aos="fade-up">
                <div class="course-image">
                    <i class="fab fa-bitcoin"></i>
                </div>
                <div class="course-content">
                    <span class="course-category">${course.category}</span>
                    <h3 class="course-title">${course.title}</h3>
                    <p class="course-description">${course.description}</p>
                    <div class="course-meta">
                        <span><i class="far fa-clock"></i> ${course.duration}</span>
                        <span><i class="far fa-play-circle"></i> ${course.lessons}</span>
                    </div>
                    <div class="course-price">
                        <span class="old-price" style="color:#aaa;text-decoration:line-through;font-size:1em;">$${course.oldPrice}</span>
                        <span class="new-price" style="color:#009e3c;font-weight:bold;font-size:1.1em;margin-left:8px;">$${course.newPrice}</span>
                        <span class="discount-badge" style="background:#ffe066;color:#b8860b;border-radius:12px;padding:2px 8px;font-size:0.9em;margin-left:6px;font-weight:600;">${course.discount}</span>
                        <a href="/buy-course.html?course=${course.key}" class="btn btn-primary" style="display:block;margin-top:10px;">Enroll Now</a>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

// Populate Blog Posts
function populateBlogs() {
    const container = document.getElementById('blog-container');
    
    container.innerHTML = blogs.map(blog => `
        <div class="blog-card" data-aos="fade-up">
            <img src="https://via.placeholder.com/400x200/3a36c4/ffffff?text=Crypto+Blog" alt="${blog.title}">
            <div class="blog-content">
                <span class="course-category">${blog.category}</span>
                <h3>${blog.title}</h3>
                <p class="blog-meta">${blog.date}</p>
                <p>${blog.excerpt}</p>
                <a href="#" class="read-more">Read More →</a>
            </div>
        </div>
    `).join('');
}

// Initialize content
document.addEventListener('DOMContentLoaded', function() {
    populateHomeCourses();
    populateAllCourses();
    populateBlogs();
});

// Simulate Market Data (in a real app, this would come from an API)
function updateMarketData() {
    // Fetch real data from CoinGecko
    fetch('https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=100&page=1&sparkline=false')
        .then(response => response.json())
        .then(data => {
            // Market stats (production: calculated from API data)
            if (data && data.length > 0) {
                const totalMarketCap = data.reduce((sum, coin) => sum + (coin.market_cap || 0), 0);
                const totalVolume = data.reduce((sum, coin) => sum + (coin.total_volume || 0), 0);
                const btc = data.find(coin => coin.symbol === 'btc');
                const eth = data.find(coin => coin.symbol === 'eth');
                document.getElementById('marketCap').textContent = '$' + totalMarketCap.toLocaleString();
                document.getElementById('volume').textContent = '$' + totalVolume.toLocaleString();
                document.getElementById('btcDominance').textContent = btc ? (btc.market_cap / totalMarketCap * 100).toFixed(1) + '%' : 'N/A';
                document.getElementById('ethDominance').textContent = eth ? (eth.market_cap / totalMarketCap * 100).toFixed(1) + '%' : 'N/A';
                document.getElementById('marketCap2').textContent = '$' + totalMarketCap.toLocaleString();
                document.getElementById('volume2').textContent = '$' + totalVolume.toLocaleString();
                document.getElementById('btcDominance2').textContent = btc ? (btc.market_cap / totalMarketCap * 100).toFixed(1) + '%' : 'N/A';
                document.getElementById('ethDominance2').textContent = eth ? (eth.market_cap / totalMarketCap * 100).toFixed(1) + '%' : 'N/A';
            }

            // Table data
            const tableBody = document.getElementById('crypto-table-body');
            const tableBody2 = document.getElementById('crypto-table-body2');
            tableBody.innerHTML = data.map((coin, i) => `
                <tr>
                    <td>${i + 1}</td>
                    <td><img src="${coin.image}" alt="${coin.symbol}" style="width:20px;height:20px;vertical-align:middle;margin-right:6px;">${coin.symbol.toUpperCase()}</td>
                    <td>$${coin.current_price.toLocaleString()}</td>
                    <td class="${coin.price_change_percentage_24h >= 0 ? 'green' : 'red'}">${coin.price_change_percentage_24h ? coin.price_change_percentage_24h.toFixed(2) : '0.00'}%</td>
                    <td>$${coin.market_cap.toLocaleString()}</td>
                </tr>
            `).join('');
            tableBody2.innerHTML = tableBody.innerHTML;

            // Update ticker (show only top 8 for brevity)
            const ticker = document.getElementById('coin-ticker');
            ticker.innerHTML = data.slice(0, 8).map(coin => {
                const isGainer = coin.price_change_percentage_24h >= 0;
                const color = isGainer ? 'green' : 'red';
                return `<span><span style="color:orange;font-weight:700;">${coin.symbol.toUpperCase()}</span>: $${coin.current_price.toLocaleString()} <span style="color:${color};font-weight:600;">${isGainer ? '+' : ''}${coin.price_change_percentage_24h ? coin.price_change_percentage_24h.toFixed(2) : '0.00'}%</span></span>`;
            }).join(' <span style="color:#888;">|</span> ');
        })
        .catch(() => {
            // fallback if API fails
            document.getElementById('crypto-table-body').innerHTML = '<tr><td colspan="5">Failed to load data.</td></tr>';
            document.getElementById('crypto-table-body2').innerHTML = '<tr><td colspan="5">Failed to load data.</td></tr>';
        });
}

// Initialize market data
updateMarketData();

// Update market data every 30 seconds (simulated)
setInterval(updateMarketData, 30000);

// Counter animation for hero stats
function animateCounters() {
    const counters = document.querySelectorAll('.stat-number');
    const speed = 200;
    
    counters.forEach(counter => {
        const target = +counter.getAttribute('data-count');
        const count = +counter.innerText;
        const increment = target / speed;
        
        if (count < target) {
            counter.innerText = Math.ceil(count + increment);
            setTimeout(animateCounters, 1);
        } else {
            counter.innerText = target;
        }
    });
}

// Start counter animation when page loads
window.addEventListener('load', animateCounters);

// Floating Dots/Stars/Boxes Animation for Hero Section (tiny and faint)
(function() {
    const canvas = document.getElementById('hero-bg-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let dpr = window.devicePixelRatio || 1;
    let width = 0, height = 0;
    function resizeCanvas() {
        width = canvas.offsetWidth;
        height = canvas.offsetHeight;
        canvas.width = width * dpr;
        canvas.height = height * dpr;
        ctx.setTransform(1, 0, 0, 1, 0, 0);
        ctx.scale(dpr, dpr);
    }
    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();

    // Config (smaller, fainter, less distracting)
    const NUM_PARTICLES = 40;
    const SHAPES = ['dot', 'star', 'box'];
    const particles = [];
    function randomBetween(a, b) { return a + Math.random() * (b - a); }
    function createParticle() {
        const shape = SHAPES[Math.floor(Math.random() * SHAPES.length)];
        return {
            x: randomBetween(0, width),
            y: randomBetween(0, height),
            vx: randomBetween(-0.15, 0.15),
            vy: randomBetween(0.08, 0.22),
            size: randomBetween(2, 6), // much smaller
            alpha: randomBetween(0.07, 0.15), // much fainter
            shape,
            rotation: randomBetween(0, Math.PI * 2),
            rotationSpeed: randomBetween(-0.01, 0.01)
        };
    }
    for (let i = 0; i < NUM_PARTICLES; i++) {
        particles.push(createParticle());
    }
    function drawStar(cx, cy, spikes, outerRadius, innerRadius, alpha) {
        let rot = Math.PI / 2 * 3;
        let x = cx;
        let y = cy;
        let step = Math.PI / spikes;
        ctx.save();
        ctx.globalAlpha = alpha;
        ctx.beginPath();
        ctx.moveTo(cx, cy - outerRadius);
        for (let i = 0; i < spikes; i++) {
            x = cx + Math.cos(rot) * outerRadius;
            y = cy - Math.sin(rot) * outerRadius;
            ctx.lineTo(x, y);
            rot += step;
            x = cx + Math.cos(rot) * innerRadius;
            y = cy - Math.sin(rot) * innerRadius;
            ctx.lineTo(x, y);
            rot += step;
        }
        ctx.lineTo(cx, cy - outerRadius);
        ctx.closePath();
        ctx.fillStyle = '#fff';
        ctx.shadowColor = '#fff';
        ctx.shadowBlur = 2;
        ctx.fill();
        ctx.restore();
    }
    function draw() {
        ctx.clearRect(0, 0, width, height);
        for (const p of particles) {
            ctx.save();
            ctx.globalAlpha = p.alpha;
            ctx.translate(p.x, p.y);
            ctx.rotate(p.rotation);
            if (p.shape === 'dot') {
                ctx.beginPath();
                ctx.arc(0, 0, p.size / 2, 0, Math.PI * 2);
                ctx.fillStyle = '#fff';
                ctx.shadowColor = '#fff';
                ctx.shadowBlur = 2;
                ctx.fill();
            } else if (p.shape === 'box') {
                ctx.fillStyle = '#fff';
                ctx.shadowColor = '#fff';
                ctx.shadowBlur = 2;
                ctx.fillRect(-p.size/2, -p.size/2, p.size, p.size);
            } else if (p.shape === 'star') {
                drawStar(0, 0, 5, p.size/2, p.size/4, p.alpha);
            }
            ctx.restore();
        }
    }
    function animate() {
        for (const p of particles) {
            p.x += p.vx;
            p.y += p.vy;
            p.rotation += p.rotationSpeed;
            if (p.y - p.size > height) {
                // Respawn at top
                p.x = randomBetween(0, width);
                p.y = -p.size;
                p.vx = randomBetween(-0.15, 0.15);
                p.vy = randomBetween(0.08, 0.22);
                p.size = randomBetween(2, 6);
                p.alpha = randomBetween(0.07, 0.15);
                p.shape = SHAPES[Math.floor(Math.random() * SHAPES.length)];
                p.rotation = randomBetween(0, Math.PI * 2);
                p.rotationSpeed = randomBetween(-0.01, 0.01);
            }
            if (p.x < -p.size) p.x = width + p.size;
            if (p.x > width + p.size) p.x = -p.size;
        }
        draw();
        requestAnimationFrame(animate);
    }
    animate();
    // Recalculate on resize
    window.addEventListener('resize', resizeCanvas);
    resizeCanvas()
})();
