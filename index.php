<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Bixen Admin Console</title>
    <style>
        :root {
            color-scheme: light;
            font-family: "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
            background: #f5f7fb;
            color: #1c2333;
        }

        body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            grid-template-columns: 260px 1fr;
        }

        aside {
            background: #101828;
            color: #f8fafc;
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        aside h1 {
            font-size: 20px;
            margin: 0 0 12px;
        }

        nav {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        nav button {
            background: transparent;
            border: 1px solid rgba(248, 250, 252, 0.2);
            color: inherit;
            padding: 10px 14px;
            border-radius: 8px;
            text-align: left;
            font-size: 14px;
            cursor: pointer;
            transition: background 0.2s ease, border-color 0.2s ease;
        }

        nav button.active,
        nav button:hover {
            background: rgba(148, 163, 184, 0.2);
            border-color: rgba(248, 250, 252, 0.4);
        }

        main {
            padding: 32px;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
        }

        header h2 {
            margin: 0;
            font-size: 24px;
        }

        .card {
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08);
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .card p {
            margin: 0;
            color: #475569;
        }

        .toolbar {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }

        .toolbar button {
            border: none;
            background: #2563eb;
            color: #fff;
            padding: 10px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
        }

        .toolbar button.secondary {
            background: #e2e8f0;
            color: #0f172a;
        }

        .modal-backdrop {
            position: fixed;
            inset: 0;
            background: rgba(15, 23, 42, 0.5);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            z-index: 10;
        }

        .modal {
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 24px 60px rgba(15, 23, 42, 0.25);
            padding: 24px;
            width: min(420px, 100%);
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .modal h3 {
            margin: 0;
            font-size: 20px;
        }

        .modal form {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .modal label {
            font-size: 13px;
            font-weight: 600;
            color: #1f2937;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .modal input,
        .modal select {
            padding: 10px 12px;
            border-radius: 8px;
            border: 1px solid #cbd5f5;
            font-size: 14px;
        }

        .modal-actions {
            display: flex;
            justify-content: flex-end;
            gap: 12px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }

        th, td {
            padding: 10px 12px;
            border-bottom: 1px solid #e2e8f0;
            text-align: left;
        }

        th {
            color: #334155;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.04em;
        }

        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 999px;
            font-weight: 600;
            font-size: 12px;
        }

        .status-allowed {
            background: #dcfce7;
            color: #166534;
        }

        .status-denied {
            background: #fee2e2;
            color: #991b1b;
        }

        .empty {
            text-align: center;
            color: #94a3b8;
            padding: 24px 0;
        }

        .hidden {
            display: none;
        }

        .inline-select {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        select {
            padding: 6px 8px;
            border-radius: 6px;
            border: 1px solid #cbd5f5;
        }

        @media (max-width: 960px) {
            body {
                grid-template-columns: 1fr;
            }

            aside {
                flex-direction: row;
                align-items: center;
                flex-wrap: wrap;
            }

            nav {
                flex-direction: row;
                flex-wrap: wrap;
            }
        }
    </style>
</head>
<body>
    <aside>
        <h1>Bixen Admin</h1>
        <nav>
            <button type="button" data-section="devices" class="active">Connected Devices</button>
            <button type="button" data-section="accounts">Accounts</button>
            <button type="button" data-section="users">Users</button>
            <button type="button" data-section="payments">Payments</button>
        </nav>
    </aside>
    <main>
        <section id="devices" class="card">
            <header>
                <div>
                    <h2>Connected Devices</h2>
                    <p>Review device connections and manage access status.</p>
                </div>
                <div class="toolbar">
                    <button type="button" data-refresh="devices">Refresh</button>
                </div>
            </header>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Device ID</th>
                            <th>Status</th>
                            <th>First Seen</th>
                            <th>Last Seen</th>
                            <th>Update</th>
                        </tr>
                    </thead>
                    <tbody data-table="devices"></tbody>
                </table>
                <div class="empty hidden" data-empty="devices">No devices have pinged yet.</div>
            </div>
        </section>

        <section id="accounts" class="card hidden">
            <header>
                <div>
                    <h2>Accounts</h2>
                    <p>View account status and toggle active access.</p>
                </div>
                <div class="toolbar">
                    <button type="button" data-refresh="accounts">Refresh</button>
                </div>
            </header>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Status</th>
                        <th>Update</th>
                    </tr>
                </thead>
                <tbody data-table="accounts"></tbody>
            </table>
            <div class="empty hidden" data-empty="accounts">No accounts found.</div>
        </section>

        <section id="users" class="card hidden">
            <header>
                <div>
                    <h2>Users</h2>
                    <p>Active users synced from the EPI endpoints.</p>
                </div>
                <div class="toolbar">
                    <button type="button" data-refresh="users">Refresh</button>
                    <button type="button" class="secondary" data-open-user-modal>Add user</button>
                </div>
            </header>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody data-table="users"></tbody>
            </table>
            <div class="empty hidden" data-empty="users">No users found.</div>
        </section>

        <div class="modal-backdrop hidden" data-user-modal>
            <div class="modal" role="dialog" aria-modal="true" aria-labelledby="add-user-title">
                <h3 id="add-user-title">Add new user</h3>
                <p>Create a new user account for this system.</p>
                <form data-user-form>
                    <label>
                        Username
                        <input type="text" name="username" required autocomplete="off">
                    </label>
                    <label>
                        Password
                        <input type="password" name="password" required autocomplete="new-password">
                    </label>
                    <label>
                        Role
                        <select name="role">
                            <option value="user" selected>User</option>
                            <option value="admin">Admin</option>
                        </select>
                    </label>
                    <div class="modal-actions">
                        <button type="button" class="secondary" data-close-user-modal>Cancel</button>
                        <button type="submit">Create user</button>
                    </div>
                </form>
            </div>
        </div>

        <div class="modal-backdrop hidden" data-edit-user-modal>
            <div class="modal" role="dialog" aria-modal="true" aria-labelledby="edit-user-title">
                <h3 id="edit-user-title">Edit user</h3>
                <p>Update the user profile details.</p>
                <form data-edit-user-form>
                    <input type="hidden" name="id">
                    <label>
                        Username
                        <input type="text" name="username" required autocomplete="off">
                    </label>
                    <label>
                        Role
                        <select name="role">
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                        </select>
                    </label>
                    <label>
                        Password (leave blank to keep current)
                        <input type="password" name="password" autocomplete="new-password">
                    </label>
                    <div class="modal-actions">
                        <button type="button" class="secondary" data-close-edit-user-modal>Cancel</button>
                        <button type="submit">Save changes</button>
                    </div>
                </form>
            </div>
        </div>

        <section id="payments" class="card hidden">
            <header>
                <div>
                    <h2>Payments</h2>
                    <p>Track synced payment entries.</p>
                </div>
                <div class="toolbar">
                    <button type="button" data-refresh="payments">Refresh</button>
                </div>
            </header>
            <table>
                <thead>
                    <tr>
                        <th>Server ID</th>
                        <th>Local ID</th>
                        <th>Account</th>
                        <th>User</th>
                        <th>Amount</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody data-table="payments"></tbody>
            </table>
            <div class="empty hidden" data-empty="payments">No payments synced yet.</div>
        </section>
    </main>

    <script>
        const sections = document.querySelectorAll('main section');
        const navButtons = document.querySelectorAll('nav button');

        const api = (action, options = {}) =>
            fetch(`api.php?action=${action}`, {
                headers: { 'Content-Type': 'application/json' },
                ...options,
            }).then(async (response) => {
                if (!response.ok) {
                    const rawBody = await response.text();
                    let parsedError = {};
                    try {
                        parsedError = rawBody ? JSON.parse(rawBody) : {};
                    } catch (parseError) {
                        parsedError = {};
                    }
                    const fallbackMessage = rawBody ? rawBody.trim() : `Request failed (${response.status})`;
                    throw new Error(parsedError.error || fallbackMessage);
                }
                return response.json();
            });

        const setEmptyState = (name, hasRows) => {
            const empty = document.querySelector(`[data-empty="${name}"]`);
            if (!empty) return;
            empty.classList.toggle('hidden', hasRows);
        };

        const formatTimestamp = (value) => (value ? new Date(value).toLocaleString() : '—');

        const handleLoadError = (name, error) => {
            console.error(error);
            const tbody = document.querySelector(`[data-table="${name}"]`);
            if (tbody) {
                tbody.innerHTML = '';
            }
            const empty = document.querySelector(`[data-empty="${name}"]`);
            if (empty) {
                empty.textContent = `Unable to load data from the API. ${error.message}`;
                empty.classList.remove('hidden');
            }
        };

        const loadDevices = async () => {
            const tbody = document.querySelector('[data-table="devices"]');
            tbody.innerHTML = '';
            let devices = [];
            try {
                devices = await api('get_devices');
            } catch (error) {
                handleLoadError('devices', error);
                return;
            }

            if (!devices.length) {
                setEmptyState('devices', false);
                return;
            }

            devices.forEach((device) => {
                const row = document.createElement('tr');
                const statusClass = device.connection_status === 'allowed' ? 'status-allowed' : 'status-denied';
                row.innerHTML = `
                    <td>${device.device_id}</td>
                    <td><span class="status-pill ${statusClass}">${device.connection_status}</span></td>
                    <td>${formatTimestamp(device.first_seen)}</td>
                    <td>${formatTimestamp(device.last_seen)}</td>
                    <td>
                        <div class="inline-select">
                            <select data-device="${device.device_id}">
                                <option value="allowed" ${device.connection_status === 'allowed' ? 'selected' : ''}>Allowed</option>
                                <option value="denied" ${device.connection_status === 'denied' ? 'selected' : ''}>Denied</option>
                            </select>
                            <button type="button" data-update-device="${device.device_id}">Save</button>
                        </div>
                    </td>
                `;
                tbody.appendChild(row);
            });

            setEmptyState('devices', true);
        };

        const loadAccounts = async () => {
            const tbody = document.querySelector('[data-table="accounts"]');
            tbody.innerHTML = '';
            let accounts = [];
            try {
                accounts = await api('get_accounts');
            } catch (error) {
                handleLoadError('accounts', error);
                return;
            }

            if (!accounts.length) {
                setEmptyState('accounts', false);
                return;
            }

            accounts.forEach((account) => {
                const row = document.createElement('tr');
                const statusText = account.active ? 'Active' : 'Inactive';
                const statusClass = account.active ? 'status-allowed' : 'status-denied';
                row.innerHTML = `
                    <td>${account.id}</td>
                    <td>${account.name}</td>
                    <td><span class="status-pill ${statusClass}">${statusText}</span></td>
                    <td>
                        <div class="inline-select">
                            <select data-account="${account.id}">
                                <option value="true" ${account.active ? 'selected' : ''}>Active</option>
                                <option value="false" ${!account.active ? 'selected' : ''}>Inactive</option>
                            </select>
                            <button type="button" data-update-account="${account.id}">Save</button>
                        </div>
                    </td>
                `;
                tbody.appendChild(row);
            });

            setEmptyState('accounts', true);
        };

        let usersCache = [];

        const loadUsers = async () => {
            const tbody = document.querySelector('[data-table="users"]');
            tbody.innerHTML = '';
            let users = [];
            try {
                users = await api('get_users');
            } catch (error) {
                handleLoadError('users', error);
                return;
            }

            if (!users.length) {
                setEmptyState('users', false);
                return;
            }

            usersCache = users;
            users.forEach((user) => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${user.id}</td>
                    <td>${user.name}</td>
                    <td>${user.role ?? 'user'}</td>
                    <td>
                        <button type="button" class="secondary" data-edit-user="${user.id}">Edit</button>
                    </td>
                `;
                tbody.appendChild(row);
            });

            setEmptyState('users', true);
        };

        const userModal = document.querySelector('[data-user-modal]');
        const userForm = document.querySelector('[data-user-form]');
        const openUserModalButton = document.querySelector('[data-open-user-modal]');
        const closeUserModalButton = document.querySelector('[data-close-user-modal]');
        const editUserModal = document.querySelector('[data-edit-user-modal]');
        const editUserForm = document.querySelector('[data-edit-user-form]');
        const closeEditUserModalButton = document.querySelector('[data-close-edit-user-modal]');

        const toggleUserModal = (shouldOpen) => {
            if (!userModal) return;
            userModal.classList.toggle('hidden', !shouldOpen);
            if (shouldOpen) {
                const firstInput = userForm?.querySelector('input[name="username"]');
                firstInput?.focus();
            } else {
                userForm?.reset();
                openUserModalButton?.focus();
            }
        };

        openUserModalButton?.addEventListener('click', () => toggleUserModal(true));
        closeUserModalButton?.addEventListener('click', () => toggleUserModal(false));
        userModal?.addEventListener('click', (event) => {
            if (event.target === userModal) {
                toggleUserModal(false);
            }
        });

        const toggleEditUserModal = (shouldOpen, user = null) => {
            if (!editUserModal) return;
            editUserModal.classList.toggle('hidden', !shouldOpen);
            if (shouldOpen && user) {
                editUserForm?.reset();
                const idInput = editUserForm?.querySelector('input[name="id"]');
                const usernameInput = editUserForm?.querySelector('input[name="username"]');
                const roleSelect = editUserForm?.querySelector('select[name="role"]');
                if (idInput) idInput.value = user.id;
                if (usernameInput) usernameInput.value = user.name ?? '';
                if (roleSelect) roleSelect.value = user.role ?? 'user';
                usernameInput?.focus();
            } else if (!shouldOpen) {
                editUserForm?.reset();
            }
        };

        closeEditUserModalButton?.addEventListener('click', () => toggleEditUserModal(false));
        editUserModal?.addEventListener('click', (event) => {
            if (event.target === editUserModal) {
                toggleEditUserModal(false);
            }
        });

        userForm?.addEventListener('submit', async (event) => {
            event.preventDefault();
            const formData = new FormData(userForm);
            const payload = {
                username: String(formData.get('username') || '').trim(),
                password: String(formData.get('password') || ''),
                role: String(formData.get('role') || 'user'),
            };

            if (!payload.username || !payload.password) {
                alert('Please provide a username and password.');
                return;
            }

            try {
                await api('add_user', {
                    method: 'POST',
                    body: JSON.stringify(payload),
                });
                toggleUserModal(false);
                await loadUsers();
            } catch (error) {
                alert(error.message || 'Unable to create user.');
            }
        });

        editUserForm?.addEventListener('submit', async (event) => {
            event.preventDefault();
            const formData = new FormData(editUserForm);
            const payload = {
                id: Number(formData.get('id')),
                username: String(formData.get('username') || '').trim(),
                role: String(formData.get('role') || 'user'),
                password: String(formData.get('password') || ''),
            };

            if (!payload.id || !payload.username) {
                alert('Please provide a username for this user.');
                return;
            }

            try {
                await api('update_user', {
                    method: 'POST',
                    body: JSON.stringify(payload),
                });
                toggleEditUserModal(false);
                await loadUsers();
            } catch (error) {
                alert(error.message || 'Unable to update user.');
            }
        });

        const loadPayments = async () => {
            const tbody = document.querySelector('[data-table="payments"]');
            tbody.innerHTML = '';
            let payments = [];
            try {
                payments = await api('get_payments');
            } catch (error) {
                handleLoadError('payments', error);
                return;
            }

            if (!payments.length) {
                setEmptyState('payments', false);
                return;
            }

            payments.forEach((payment) => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${payment.server_id}</td>
                    <td>${payment.local_id ?? '—'}</td>
                    <td>${payment.account_name}</td>
                    <td>${payment.user_name}</td>
                    <td>${payment.amount}</td>
                    <td>${formatTimestamp(payment.timestamp)}</td>
                `;
                tbody.appendChild(row);
            });

            setEmptyState('payments', true);
        };

        const refreshHandlers = {
            devices: loadDevices,
            accounts: loadAccounts,
            users: loadUsers,
            payments: loadPayments,
        };

        navButtons.forEach((button) => {
            button.addEventListener('click', () => {
                const target = button.dataset.section;
                navButtons.forEach((btn) => btn.classList.toggle('active', btn === button));
                sections.forEach((section) => section.classList.toggle('hidden', section.id !== target));
                refreshHandlers[target]?.();
            });
        });

        document.addEventListener('click', async (event) => {
            const refresh = event.target.closest('[data-refresh]');
            if (refresh) {
                const target = refresh.dataset.refresh;
                refreshHandlers[target]?.();
                return;
            }

            const updateDevice = event.target.closest('[data-update-device]');
            if (updateDevice) {
                const deviceId = updateDevice.dataset.updateDevice;
                const select = document.querySelector(`[data-device="${deviceId}"]`);
                if (!select) return;
                await api('update_status', {
                    method: 'POST',
                    body: JSON.stringify({ deviceId, connectionStatus: select.value }),
                });
                await loadDevices();
                return;
            }

            const updateAccount = event.target.closest('[data-update-account]');
            if (updateAccount) {
                const accountId = Number(updateAccount.dataset.updateAccount);
                const select = document.querySelector(`[data-account="${accountId}"]`);
                if (!select) return;
                await api('update_account_status', {
                    method: 'POST',
                    body: JSON.stringify({ accountId, isActive: select.value === 'true' }),
                });
                await loadAccounts();
                return;
            }

            const editUserButton = event.target.closest('[data-edit-user]');
            if (editUserButton) {
                const userId = Number(editUserButton.dataset.editUser);
                const user = usersCache.find((entry) => entry.id === userId);
                if (!user) return;
                toggleEditUserModal(true, user);
            }
        });

        loadDevices();
    </script>
</body>
</html>
