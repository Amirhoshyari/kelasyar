```javascript
// دکمه‌های صفحه اصلی کلاس‌یار

const loginBtn = document.getElementById("loginBtn");
const registerBtn = document.getElementById("registerBtn");
const heroRegisterBtn = document.getElementById("heroRegisterBtn");
const featuresBtn = document.getElementById("featuresBtn");

// فعلاً این دکمه‌ها نمایشی هستند.
// در مرحله بعد آن‌ها را به صفحات ورود و ثبت‌نام واقعی متصل می‌کنیم.

loginBtn.addEventListener("click", function () {
    alert("صفحه ورود را در مرحله بعد می‌سازیم.");
});

registerBtn.addEventListener("click", function () {
    alert("صفحه ثبت‌نام معلم را در مرحله بعد می‌سازیم.");
});

heroRegisterBtn.addEventListener("click", function () {
    alert("به‌زودی می‌توانی حساب معلم خودت را بسازی.");
});

featuresBtn.addEventListener("click", function () {
    document.getElementById("features").scrollIntoView({
        behavior: "smooth"
    });
});
```
