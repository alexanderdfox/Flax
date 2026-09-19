function changeText() {
    const msg = document.getElementById('message');
    msg.textContent = 'CSS and JavaScript are fully operational via the kernel!';
    msg.style.color = '#38bdf8';
}
document.addEventListener('DOMContentLoaded', () => {
    console.log("Metamorphic client script loaded.");
});