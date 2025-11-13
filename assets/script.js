const app = {
    currentUser: null,
    map: null,
    scrollInterval: null,

    qs(selector) { return document.querySelector(selector); },
    qsa(selector) { return Array.from(document.querySelectorAll(selector)); },
    
    safeAddEvent(el, event, handler) { 
        if (el) el.addEventListener(event, handler); 
    },

    async checkAuth() {
        try {
            const resp = await fetch('/api/me');
            if (resp.ok) {
                const user = await resp.json();
                this.currentUser = user;
                
                this.loadNotifications();
            } else {
                this.currentUser = null;
            }
        } catch (err) {
            this.currentUser = null;
            console.warn('checkAuth error', err);
        }
        this.updateUserInterface();
    },

    updateUserInterface() {
        const userProfileText = this.qs('#user-profile-text');
        const notificationBell = this.qs('#notification-bell');
        
        if (this.currentUser) {
            if (userProfileText) {
                userProfileText.textContent = this.currentUser.username || this.currentUser.email;
            }
            if (notificationBell) {
                notificationBell.style.display = 'flex';
            }
        } else {
            if (userProfileText) {
                userProfileText.textContent = 'Личный кабинет';
            }
            if (notificationBell) {
                notificationBell.style.display = 'none';
            }
            this.updateNotificationBadge(0);
        }
    },

    getNotificationsKey() {
        if (!this.currentUser) return null;
        return `user_notifications_${this.currentUser.id}`;
    },

    createWelcomeNotification() {
        try {
            if (!this.currentUser) return;
            
            const notificationsKey = this.getNotificationsKey();
            const notifications = JSON.parse(localStorage.getItem(notificationsKey) || '[]');
            
            const welcomeNotification = {
                id: Date.now(),
                title: 'Добро пожаловать!',
                message: `Вы успешно зарегистрировались в системе личного кабинета как ${this.currentUser.username}. Теперь вам доступны все функции сайта.`,
                time: 'Только что',
                read: false,
                type: 'welcome',
                createdAt: new Date().toISOString()
            };
            
            notifications.unshift(welcomeNotification);
            
            localStorage.setItem(notificationsKey, JSON.stringify(notifications));
            
            console.log('Приветственное уведомление создано для пользователя:', this.currentUser.id);
        } catch (err) {
            console.error('Ошибка создания уведомления:', err);
        }
    },

    async loadNotifications() {
        if (!this.currentUser) {
            this.displayNotifications([]);
            return;
        }
        
        try {
            const notificationsKey = this.getNotificationsKey();
            const notifications = JSON.parse(localStorage.getItem(notificationsKey) || '[]');
            
            const updatedNotifications = notifications.map(notification => ({
                ...notification,
                time: this.formatTimeAgo(notification.createdAt)
            }));
            
            this.displayNotifications(updatedNotifications);
        } catch (err) {
            console.error('Ошибка загрузки уведомлений:', err);
            this.displayNotifications([]);
        }
    },

    markNotificationAsRead(notificationId) {
        try {
            if (!this.currentUser) return;
            
            const notificationsKey = this.getNotificationsKey();
            const notifications = JSON.parse(localStorage.getItem(notificationsKey) || '[]');
            const updatedNotifications = notifications.map(notification => 
                notification.id == notificationId ? { ...notification, read: true } : notification
            );
            
            localStorage.setItem(notificationsKey, JSON.stringify(updatedNotifications));
            
            const notificationItem = this.qs(`.notification-item[data-id="${notificationId}"]`);
            if (notificationItem) {
                notificationItem.classList.remove('unread');
                
                const currentCount = parseInt(this.qs('#notification-badge').textContent) || 0;
                const newCount = Math.max(0, currentCount - 1);
                this.updateNotificationBadge(newCount);
            }
        } catch (err) {
            console.error('Ошибка отметки уведомления как прочитанного:', err);
        }
    },

    setupAuthForms() {
        const registerForm = this.qs('#register-form');
        const loginForm = this.qs('#login-form');

        if (registerForm) {
            this.safeAddEvent(registerForm, 'submit', async (e) => {
                e.preventDefault();
                
                const email = document.getElementById('register-email').value;
                const username = document.getElementById('register-username').value;
                const password = document.getElementById('register-password').value;
                const passwordRepeat = document.getElementById('register-password-repeat').value;

                if (password !== passwordRepeat) {
                    this.showMessage('Пароли не совпадают', 'error');
                    return;
                }

                try {
                    const res = await fetch('/api/register', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email, username, password, passwordRepeat })
                    });

                    const data = await res.json();

                    if (!res.ok) {
                        this.showMessage(data.error, 'error');
                        return;
                    }

                    document.getElementById('register-success').style.display = 'block';

                    setTimeout(() => {
                        this.closeModalById('register-modal');
                        this.checkAuth().then(() => {
                            this.createWelcomeNotification();
                            this.showMessage('Успешная регистрация!', 'success');
                        });
                    }, 1200);
                } catch (err) {
                    this.showMessage('Ошибка сети', 'error');
                }
            });
        }

        if (loginForm) {
            this.safeAddEvent(loginForm, 'submit', async (e) => {
                e.preventDefault();
                
                const email = document.getElementById('login-email').value;
                const password = document.getElementById('login-password').value;

                try {
                    const res = await fetch('/api/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email, password })
                    });

                    const data = await res.json();

                    if (!res.ok) {
                        this.showMessage(data.error, 'error');
                        return;
                    }

                    this.closeModalById('login-modal');
                    this.checkAuth();
                    this.showMessage('Успешный вход!', 'success');
                } catch (err) {
                    this.showMessage('Ошибка сети', 'error');
                }
            });
        }
    },

    
    openModalById(id) {
        this.qsa('.modal').forEach(modal => {
            modal.style.display = 'none';
        });
        
        const el = document.getElementById(id);
        if (el) {
            el.style.display = 'block';
            el.style.zIndex = '10000';
            if (el.querySelector('.modal-content')) {
                el.querySelector('.modal-content').style.zIndex = '10001';
            }
        }
    },

    closeModalById(id) {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    },

    closeModal(modalId) {
        this.closeModalById(modalId);
    },

    setupCloseModalButtons() {
        this.qsa('.close-modal').forEach(btn => {
            this.safeAddEvent(btn, 'click', (e) => {
                const modalId = btn.dataset.modal;
                if (modalId) {
                    this.closeModalById(modalId);
                } else {
                    const modal = btn.closest('.modal');
                    if (modal) modal.style.display = 'none';
                }
            });
        });
    },

    setupWindowModalClick() {
        this.safeAddEvent(window, 'click', (e) => {
            if (e.target && e.target.classList && e.target.classList.contains('modal')) {
                e.target.style.display = 'none';
            }
        });
    },

    showMessage(message, type = 'success') {
        const old = this.qsa('.error-message, .success-message');
        old.forEach(o => o.remove());

        const div = document.createElement('div');
        div.className = type === 'error' ? 'error-message' : 'success-message';
        div.textContent = message;

        const activeModal = this.qsa('.modal').find(m => m.style.display === 'block');
        if (activeModal) {
            const form = activeModal.querySelector('form');
            if (form) form.insertBefore(div, form.firstChild);
            else activeModal.querySelector('.modal-content').prepend(div);
        } else {
            document.body.appendChild(div);
        }

        setTimeout(() => div.remove(), 5000);
    },

    switchToLogin() {
        this.closeModalById('register-modal');
        this.openModalById('login-modal');
    },

    switchToRegister() {
        this.closeModalById('login-modal');
        this.openModalById('register-modal');
    },

    initMapIfNeeded() {
        if (this.map) return;
        if (!window.ymaps) {
            console.warn('ymaps not loaded');
            return;
        }
        
        const latitude = 59.916809;
        const longitude = 30.310717;

        ymaps.ready(() => {
            try {
                this.map = new ymaps.Map('map', {
                    center: [latitude, longitude],
                    zoom: 16,
                    controls: ['zoomControl']
                }, {
                    suppressMapOpenBlock: true,
                    suppressObsoleteBrowserNotifier: true,
                    yandexMapDisablePoiInteractivity: true
                });

                this.map.behaviors.disable([
                    'rightMouseButtonMagnifier',
                    'dblClickZoom'
                ]);
                
                const marker = new ymaps.Placemark([latitude, longitude], {
                    hintContent: 'Кафедра О7',
                    balloonContent: '1-я Красноармейская улица, 13В<br>Учебно-лабораторный корпус, 2 этаж'
                }, {
                    preset: 'islands#blueIcon'
                });

                this.map.geoObjects.add(marker);
                
                console.log('✅ Карта инициализирована на странице контактов');
            } catch (err) {
                console.error('ymaps init error', err);
            }
        });
    },

    
    formatTimeAgo(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);

        if (diffMins < 1) return 'Только что';
        if (diffMins < 60) return `${diffMins} мин. назад`;
        if (diffHours < 24) return `${diffHours} ч. назад`;
        if (diffDays === 1) return 'Вчера';
        if (diffDays < 7) return `${diffDays} дн. назад`;
        
        return date.toLocaleDateString('ru-RU');
    },

    fillEvents(eventsData) {
        const evWrap = this.qs('#events-container');
        if (!evWrap) return;
        
        evWrap.innerHTML = '';
        eventsData.forEach(e => {
            const d = document.createElement('div');
            d.className = 'event';
            d.innerHTML = `
                <div class="event-date">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M8 7V3M16 7V3M7 11H17M5 21H19C20.1046 21 21 20.1046 21 19V7C21 5.89543 20.1046 5 19 5H5C3.89543 5 3 5.89543 3 7V19C3 20.1046 3.89543 21 5 21Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    ${e.date}, ${e.time}
                </div>
                <div class="event-place">${e.place}</div>
                <div class="event-desc">${e.desc}</div>`;
            evWrap.appendChild(d);
        });
    },

    generateCurrentEvents() {
        const now = new Date();
        const events = [];
        
        for (let i = 1; i <= 5; i++) {
            const eventDate = new Date(now);
            eventDate.setDate(now.getDate() + i);
            
            const days = ['воскресенье', 'понедельник', 'вторник', 'среда', 'четверг', 'пятница', 'суббота'];
            const months = ['января', 'февраля', 'марта', 'апреля', 'мая', 'июня', 'июля', 'августа', 'сентября', 'октября', 'ноября', 'декабря'];
            
            const dateStr = `${eventDate.getDate()} ${months[eventDate.getMonth()]}`;
            const timeOptions = ['10:00', '12:00', '14:00', '16:00', '18:00'];
            const places = ['Ауд. 302', 'Актовый зал', 'Онлайн', 'Лаб. 204', 'Ауд. 415'];
            const descriptions = [
                'Мастер-класс по Python и анализу данных',
                'День открытых дверей кафедры',
                'Вебинар по кибербезопасности',
                'Практикум по нейросетям и машинному обучению',
                'Семинар по разработке мобильных приложений'
            ];
            
            events.push({
                date: dateStr,
                time: timeOptions[i-1],
                place: places[i-1],
                desc: descriptions[i-1]
            });
        }
        
        return events;
    },

    setupContactForm() {
        const feedbackForm = this.qs('#feedback-form');

        if (feedbackForm) {
            this.safeAddEvent(feedbackForm, 'submit', (e) => {
                e.preventDefault();
                const fd = new FormData(feedbackForm);
                const payload = {
                    name: fd.get('name'),
                    email: fd.get('email'),
                    subject: fd.get('subject'),
                    message: fd.get('message')
                };
                
                this.saveContactFormToDB(payload);
                
                console.log('Данные формы:', payload);
                alert('Ваше сообщение отправлено! Мы свяжемся с вами в ближайшее время.');
                feedbackForm.reset();
            });
        }
    },

    saveContactFormToDB(formData) {
        try {
            const existingData = JSON.parse(localStorage.getItem('contact_forms') || '[]');
            
            const newEntry = {
                ...formData,
                id: Date.now(),
                timestamp: new Date().toISOString(),
                status: 'new'
            };
            
            existingData.push(newEntry);
            localStorage.setItem('contact_forms', JSON.stringify(existingData));
            
            console.log('Форма сохранена в БД (localStorage):', newEntry);
        } catch (err) {
            console.error('Ошибка сохранения формы:', err);
        }
    },

    setupScheduleModal() {
        const scheduleModal = this.qs('#schedule-modal');
        const scheduleBlock = this.qs('.schedule-block');
        const consultationsLink = this.qs('#consultations-link');
        const breadcrumbs = this.qs('#breadcrumbs');
        
        const mainContent = this.qs('#main-content');
        
        const consultationsPage = this.qs('#consultations-page');
        const breadcrumbMain = this.qs('#breadcrumb-main');

        if (scheduleBlock && scheduleModal) {
            this.safeAddEvent(scheduleBlock, 'click', () => { 
                scheduleModal.style.display = 'block'; 
            });
        }

        if (consultationsLink) {
            this.safeAddEvent(consultationsLink, 'click', (e) => {
                e.preventDefault();
                if (scheduleModal) scheduleModal.style.display = 'none';
                if (mainContent) mainContent.style.display = 'none';
                if (consultationsPage) consultationsPage.style.display = 'block';
                if (breadcrumbs) breadcrumbs.style.display = 'block';
                
                window.history.pushState({ page: 'consultations' }, '', '/consultations');
            });
        }

        if (breadcrumbMain) {
            this.safeAddEvent(breadcrumbMain, 'click', (e) => {
                e.preventDefault();
                this.showMainPage();
            });
        }

        window.addEventListener('popstate', (event) => {
            const path = window.location.pathname;
            if (path === '/consultations') {
                this.showConsultationsPage();
            } else if (path === '/contacts') {
                this.showContactsPage();
            } else {
                this.showMainPage();
            }
        });
    },

    showMainPage() {
        const mainContent = this.qs('#main-content');
        const consultationsPage = this.qs('#consultations-page');
        const contactsPage = this.qs('#contacts-page');
        const breadcrumbs = this.qs('#breadcrumbs');
        const scheduleModal = this.qs('#schedule-modal');

        if (mainContent) mainContent.style.display = 'block';
        if (consultationsPage) consultationsPage.style.display = 'none';
        if (contactsPage) contactsPage.style.display = 'none';
        if (breadcrumbs) breadcrumbs.style.display = 'none';
        if (scheduleModal) scheduleModal.style.display = 'none';
        
        window.history.pushState({ page: 'main' }, '', '/');
    },

    showConsultationsPage() {
        const mainContent = this.qs('#main-content');
        const consultationsPage = this.qs('#consultations-page');
        const contactsPage = this.qs('#contacts-page');
        const breadcrumbs = this.qs('#breadcrumbs');
        const scheduleModal = this.qs('#schedule-modal');

        if (mainContent) mainContent.style.display = 'none';
        if (consultationsPage) consultationsPage.style.display = 'block';
        if (contactsPage) contactsPage.style.display = 'none';
        if (breadcrumbs) breadcrumbs.style.display = 'block';
        if (scheduleModal) scheduleModal.style.display = 'none';
        
        window.history.pushState({ page: 'consultations' }, '', '/consultations');
    },

    showContactsPage() {
        const mainContent = this.qs('#main-content');
        const consultationsPage = this.qs('#consultations-page');
        const contactsPage = this.qs('#contacts-page');
        const breadcrumbs = this.qs('#breadcrumbs');
        const scheduleModal = this.qs('#schedule-modal');

        if (mainContent) mainContent.style.display = 'none';
        if (consultationsPage) consultationsPage.style.display = 'none';
        if (contactsPage) contactsPage.style.display = 'block';
        if (breadcrumbs) breadcrumbs.style.display = 'none';
        if (scheduleModal) scheduleModal.style.display = 'none';
        
        setTimeout(() => {
            this.initMapIfNeeded();
        }, 100);
        
        window.history.pushState({ page: 'contacts' }, '', '/contacts');
    },

    setupMapToggle() {
        const mapContainer = this.qs('#map-container');
        const addressLink = this.qs('#address-link');
        const closeMap = this.qs('#close-map');

        if (addressLink && mapContainer) {
            this.safeAddEvent(addressLink, 'click', (e) => {
                e.preventDefault();
                mapContainer.classList.add('expanded');
                this.initMapIfNeeded();
            });
        }

        if (closeMap && mapContainer) {
            this.safeAddEvent(closeMap, 'click', () => {
                mapContainer.classList.remove('expanded');
            });
        }
    },

    setupPrivacyPage() {
        const privacyLink = this.qs('#privacy-link');
        const footerPrivacyLink = this.qs('#footer-privacy-link');
        
        const mainContent = this.qs('#main-content');
        
        const privacySection = this.qs('#privacy');
        const breadcrumbs = this.qs('#breadcrumbs');

        const showPrivacyPage = () => {
            if (mainContent) mainContent.style.display = 'none';
            if (privacySection) privacySection.style.display = 'block';
            if (breadcrumbs) {
                breadcrumbs.style.display = 'block';
                breadcrumbs.innerHTML = `
                    <ul>
                        <li><a href="/" id="breadcrumb-main-privacy">Главная</a></li>
                        <li><span>Политика конфиденциальности</span></li>
                    </ul>
                `;
                
                const mainBreadcrumb = this.qs('#breadcrumb-main-privacy');
                if (mainBreadcrumb) {
                    this.safeAddEvent(mainBreadcrumb, 'click', (e) => {
                        e.preventDefault();
                        this.showMainPage();
                    });
                }
            }
            
            const footer = this.qs('footer');
            if (footer) footer.style.display = 'none';
        };

        const showMainPage = () => {
            if (mainContent) mainContent.style.display = 'block';
            if (privacySection) privacySection.style.display = 'none';
            if (breadcrumbs) breadcrumbs.style.display = 'none';
            
            const footer = this.qs('footer');
            if (footer) footer.style.display = 'block';
        };

        if (privacyLink) {
            this.safeAddEvent(privacyLink, 'click', (e) => {
                e.preventDefault();
                showPrivacyPage();
            });
        }

        if (footerPrivacyLink) {
            this.safeAddEvent(footerPrivacyLink, 'click', (e) => {
                e.preventDefault();
                showPrivacyPage();
            });
        }
    },

    setupNotifications() {
        const notificationBell = this.qs('#notification-bell');
        const notificationsModal = this.qs('#notifications-modal');

        if (notificationBell && notificationsModal) {
            this.safeAddEvent(notificationBell, 'click', (e) => {
                e.stopPropagation();
                if (this.currentUser) {
                    this.loadNotifications();
                    notificationsModal.style.display = 'block';
                }
            });
        }
    },

    displayNotifications(notifications) {
        const container = this.qs('#notifications-list');
        if (!container) return;

        // Фильтруем только непрочитанные уведомления для бейджа
        const unreadCount = notifications.filter(n => !n.read).length;
        this.updateNotificationBadge(unreadCount);

        if (notifications.length === 0) {
            container.innerHTML = `
                <div class="notification-item">
                    <div class="notification-text" style="text-align: center; color: var(--text-muted);">
                        Уведомлений нет
                    </div>
                </div>
            `;
            return;
        }

        container.innerHTML = notifications.map(notification => `
            <div class="notification-item ${notification.read ? '' : 'unread'}" 
                 data-id="${notification.id}">
                <div class="notification-title">${notification.title}</div>
                <div class="notification-text">${notification.message}</div>
                <div class="notification-time">${notification.time}</div>
            </div>
        `).join('');

        // Добавляем обработчики кликов для уведомлений
        this.qsa('.notification-item').forEach(item => {
            this.safeAddEvent(item, 'click', () => {
                this.markNotificationAsRead(item.dataset.id);
            });
        });
    },

    updateNotificationBadge(count) {
        const badge = this.qs('#notification-badge');
        if (badge) {
            if (count > 0) {
                badge.textContent = count > 99 ? '99+' : count;
                badge.style.display = 'flex';
            } else {
                badge.style.display = 'none';
            }
        }
    },

    setupUserProfile() {
        const userProfileEl = this.qs('#user-profile');
        const logoutBtn = this.qs('#logout-btn');

        if (userProfileEl) {
            this.safeAddEvent(userProfileEl, 'click', () => {
                if (this.currentUser) {
                    this.openModalById('profile-modal');
                    const uName = this.qs('#profile-username');
                    const uEmail = this.qs('#profile-email');
                    const uRole = this.qs('#profile-role');
                    if (uName) uName.textContent = this.currentUser.username || '';
                    if (uEmail) uEmail.textContent = this.currentUser.email || '';
                    if (uRole) uRole.textContent = this.currentUser.role || 'Пользователь';
                } else {
                    this.openModalById('login-modal');
                }
            });
        }

        if (logoutBtn) {
            this.safeAddEvent(logoutBtn, 'click', async () => {
                try {
                    await fetch('/api/logout', { method: 'POST' });
                    this.currentUser = null;
                    this.updateUserInterface();
                    this.closeModalById('profile-modal');
                    this.showMessage('Вы вышли из системы', 'success');
                } catch (err) {
                    this.showMessage('Ошибка при выходе', 'error');
                }
            });
        }
    },

    setupContactsNavigation() {
        const contactsLink = this.qs('#contacts-link');
        const contactsBackButton = this.qs('#contacts-back-button');
        const contactFormToggle = this.qs('#contact-form-toggle');
        const backButton = this.qs('#back-button');

        if (contactsLink) {
            this.safeAddEvent(contactsLink, 'click', (e) => {
                e.preventDefault();
                this.showContactsPage();
            });
        }

        if (contactsBackButton) {
            this.safeAddEvent(contactsBackButton, 'click', (e) => {
                e.preventDefault();
                this.showMainPage();
            });
        }

        if (backButton) {
            this.safeAddEvent(backButton, 'click', (e) => {
                e.preventDefault();
                this.showMainPage();
            });
        }

        if (contactFormToggle) {
            this.safeAddEvent(contactFormToggle, 'click', (e) => {
                e.preventDefault();
                const contactForm = this.qs('.contact-form');
                if (contactForm) {
                    contactForm.scrollIntoView({ behavior: 'smooth' });
                }
            });
        }
    },

    async init() {
        console.log('Инициализация приложения...');
        
        await this.checkAuth();
        
        this.setupCloseModalButtons();
        this.setupWindowModalClick();
        this.setupAuthForms();
        this.setupContactForm();
        this.setupScheduleModal();
        this.setupMapToggle();
        this.setupPrivacyPage();
        this.setupNotifications();
        this.setupUserProfile();
        this.setupContactsNavigation();

        // Проверяем текущий URL при загрузке
        const path = window.location.pathname;
        if (path === '/contacts') {
            this.showContactsPage();
        } else if (path === '/consultations') {
            this.showConsultationsPage();
        } else {
            this.showMainPage();
        }

        // Заполняем мероприятия актуальными датами
        const currentEvents = this.generateCurrentEvents();
        this.fillEvents(currentEvents);

        console.log('Приложение инициализировано');
    }
};

document.addEventListener('DOMContentLoaded', () => {
    app.init();
});