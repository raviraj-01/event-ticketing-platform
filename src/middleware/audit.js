// H6: log successful admin changes (see src/services/adminAudit.js).
const { audited } = require("../services/adminAudit");
const { pool } = require("../db/pool");

const audit = (action, describe) => audited(pool, action, describe);

module.exports = { audit };
