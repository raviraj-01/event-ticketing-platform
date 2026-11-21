// Turn database rows into the JSON shapes the API returns (camelCase, only the
// fields a client may see).
const publicUser = (user) => ({
  id: user.id,
  username: user.username,
  firstName: user.first_name,
  lastName: user.last_name,
  email: user.email,
  phone: user.phone,
  countryCode: user.country_code,
  city: user.city,
  profileImage: user.profile_image_url,
  profileImageKey: user.profile_image_key,
  profileImageStorage: user.profile_image_storage,
  status: user.status || "Active",
});

const EVENT_NOT_FOUND_ERROR = "Event does not exist";
const USER_NOT_FOUND_ERROR = "User account not found";



const publicCreator = (creator) => ({
  id: creator.id,
  name: creator.name,
  email: creator.email,
  phone: creator.phone,
  category: creator.category,
  about: creator.about,
  kycStatus: creator.kyc_status,
  joinedAt: creator.created_at,
});

// KYC scans (Aadhaar, PAN, bank) are never public: they are opened through
// an authenticated, audited super-admin route (H14).
const creatorKycDocumentUrl = (document) =>
  document && document.id ? `/admin/kyc-documents/${encodeURIComponent(document.id)}/file` : "";

const publicCreatorKycDocument = (document) => ({
  id: document.id,
  documentType: document.document_type,
  fileName: document.file_name,
  contentType: document.content_type,
  storage: document.storage,
  url: creatorKycDocumentUrl(document),
  verificationStatus: document.verification_status || "Pending",
  verifiedAt: document.verified_at,
  verifiedBy: document.verified_by,
  createdAt: document.created_at,
});

const publicAdminCreator = (creator) => ({
  id: `CRT-${creator.id}`,
  creatorId: creator.id,
  name: creator.name,
  email: creator.email,
  phone: creator.phone,
  category: creator.category,
  status: creator.kyc_status,
  events: Number(creator.events || 0),
  revenue: Number(creator.revenue || 0),
  fee: 8,
  documents: (creator.documents || []).map(publicCreatorKycDocument),
  createdAt: creator.created_at,
});

const publicCreatorEvent = (event) => ({
  id: event.id,
  creatorId: event.creator_id,
  creatorName: event.creator_name,
  name: event.name,
  category: event.category,
  description: event.description,
  date: event.event_date,
  time: event.start_time,
  endTime: event.end_time,
  venue: event.venue,
  city: event.city,
  capacity: event.capacity,
  latitude: event.latitude,
  longitude: event.longitude,
  banner: event.banner_url,
  bannerKey: event.banner_key,
  visibility: event.visibility,
  status: event.status,
  tickets: event.tickets || [],
  bookingCount: Number(event.booking_count || 0),
  revenue: Number(event.revenue || 0),
  checkins: Number(event.checkins || 0),
  createdAt: event.created_at,
});



const publicStaffAssignment = (assignment) => ({
  id: assignment.id,
  staffPk: assignment.staff_id,
  staffId: assignment.staff_id,
  eventId: assignment.event_id,
  eventName: assignment.event_name,
  tierName: assignment.tier_name,
  qty: Number(assignment.qty || 0),
  soldCount: Number(assignment.sold_count || 0),
  price: Number(assignment.price || 0),
  mode: assignment.allocation_mode || "creator_quota",
  allocationMode: assignment.allocation_mode || "creator_quota",
  commissionRate: Number(assignment.commission_rate || 0),
  purchasePrice: Number(assignment.purchase_price || assignment.price || 0),
  resalePrice: Number(assignment.resale_price || assignment.price || 0),
  assignedAt: assignment.created_at,
});

const publicStaffShareUrl = (req, member) => {
  if (!member || !member.share_token) return "";
  const origin = req ? `${req.protocol}://${req.get("host")}` : "";
  const eventId = member.primary_event_id
    ? `&event=${encodeURIComponent(member.primary_event_id)}`
    : "";
  return `${origin}/?staff=${encodeURIComponent(member.share_token)}${eventId}`;
};

const publicStaffSale = (sale) => ({
  id: sale.id,
  staffPk: sale.staff_id,
  assignmentId: sale.assignment_id,
  eventId: sale.event_id,
  eventName: sale.event_name,
  tierName: sale.tier_name,
  buyerName: sale.buyer_name,
  buyerPhone: sale.buyer_phone,
  buyerEmail: sale.buyer_email,
  qty: Number(sale.qty || 0),
  price: Number(sale.price || 0),
  total: Number(sale.total || 0),
  commission: Number(sale.commission || 0),
  revenueOwner: sale.revenue_owner || "staff",
  allocationMode: sale.allocation_mode || "creator_quota",
  paymentMode: sale.payment_mode,
  bookingId: sale.booking_id,
  soldAt: sale.created_at,
});

const publicStaffWithdrawal = (withdrawal) => ({
  id: withdrawal.id,
  staffPk: withdrawal.staff_id,
  amount: Number(withdrawal.amount || 0),
  method: withdrawal.method,
  bankAccountName: withdrawal.bank_account_name,
  bankAccountNumber: withdrawal.bank_account_number,
  bankIfsc: withdrawal.bank_ifsc,
  upiId: withdrawal.upi_id,
  status: withdrawal.status,
  requestedAt: withdrawal.created_at,
});

const publicStaff = (member) => ({
  id: member.id,
  creatorId: member.creator_id,
  name: member.name,
  staffId: member.staff_id,
  email: member.email,
  phone: member.phone,
  role: member.role,
  assignedGate: member.assigned_gate,
  gates: member.assigned_gate ? [member.assigned_gate] : [],
  primaryEventId: member.primary_event_id,
  shareToken: member.share_token,
  shareUrl: member.share_url || "",
  status: member.status,
  assignedTickets: Number(member.assigned_tickets || 0),
  soldTickets: Number(member.sold_tickets || 0),
  earnings: Number(member.earnings || 0),
  cashOwed: Number(member.cash_owed || 0),
  createdByAdminEmail: member.created_by_admin_email || null,
  createdAt: member.created_at,
});

const publicAdmin = (admin) => ({
  id: admin.id,
  name: admin.name,
  email: admin.email,
  role: admin.role,
  isSuperAdmin: Boolean(admin.is_super_admin),
  status: admin.status,
  lastLogin: admin.last_login,
  createdAt: admin.created_at,
});

module.exports = {
  publicCreator,
  publicCreatorEvent,
  publicStaff,
  publicStaffShareUrl,
  publicStaffAssignment,
  publicStaffSale,
  publicStaffWithdrawal,
  EVENT_NOT_FOUND_ERROR,
  publicAdmin,
  publicAdminCreator,
  USER_NOT_FOUND_ERROR,
  publicUser,
  publicCreatorKycDocument,
};
