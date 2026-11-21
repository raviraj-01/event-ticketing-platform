// Account status rules shared by routes and the session service.

const USER_ACTIVE_STATUS = "Active";
const USER_BLOCKED_STATUSES = new Set(["Suspended", "Blocked", "Inactive"]);

const normalizeUserStatus = (status) => String(status || USER_ACTIVE_STATUS).trim();

// Buyers are active unless explicitly blocked.
const isUserActive = (status) => !USER_BLOCKED_STATUSES.has(normalizeUserStatus(status));

module.exports = { USER_ACTIVE_STATUS, normalizeUserStatus, isUserActive };
