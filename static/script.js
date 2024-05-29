// script.js

document.addEventListener('DOMContentLoaded', () => {
    const header = document.querySelector('header');
    const footer = document.querySelector('footer');
    let lastScrollTop = 0;
    const headerThreshold = 20; // 20% scroll threshold for hiding header
    const footerThreshold = 90; // 90% scroll threshold for showing footer

    const checkScroll = () => {
        const currentScroll = window.pageYOffset || document.documentElement.scrollTop;
        const windowHeight = window.innerHeight;
        const documentHeight = document.documentElement.scrollHeight;
        const scrolledPercentage = (currentScroll / (documentHeight - windowHeight)) * 100;

        // Hide header after 20% scroll
        if (scrolledPercentage > headerThreshold) {
            header.style.transform = 'translateY(-100%)';
        } else {
            header.style.transform = 'translateY(0)';
        }

        // Show footer after 90% scroll
        if (scrolledPercentage > footerThreshold) {
            footer.style.transform = 'translateY(0)';
        } else {
            footer.style.transform = 'translateY(100%)';
        }

        lastScrollTop = currentScroll <= 0 ? 0 : currentScroll; // For Mobile or negative scrolling
    };

    window.addEventListener('scroll', checkScroll);

    // Initially hide the footer
    footer.style.transform = 'translateY(100%)';
});
