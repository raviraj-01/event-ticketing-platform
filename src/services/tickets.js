// Ticket JSON sent to clients: booking fields plus the QR payload and image.
const QRCode = require("qrcode");

const makeTicketQrPayload = (bookingId, token, eventId = "") =>
  `VYBERA-TICKET|${bookingId}|${eventId || "NOEVENT"}|${token}`;

const ticketResponse = async (booking) => {
  const qrPayload = makeTicketQrPayload(booking.id, booking.qr_token, booking.event_id);
  return {
    id: booking.id,
    buyerName: booking.buyer_name || booking.buyer_email || "BLAK Tickets Guest",
    buyerEmail: booking.buyer_email,
    eventId: booking.event_id,
    eventName: booking.event_name,
    eventDate: booking.event_date,
    eventVenue: booking.event_venue,
    eventBanner: booking.event_banner,
    ticketType: booking.ticket_type,
    price: Number(booking.price || 0),
    qty: Number(booking.qty || 1),
    total: Number(booking.total || 0),
    status: booking.status,
    scannedAt: booking.scanned_at,
    qrPayload,
    qrImage: await QRCode.toDataURL(qrPayload, {
      width: 320,
      margin: 2,
      errorCorrectionLevel: "M",
    }),
  };
};

module.exports = { ticketResponse };
