// src/index.js
export default {
  async email(message, env, ctx) {
    const targetEmail = "justin@ooheynerds.com";
    const forwardTo = "jukasdrj@gmail.com";
    
    // Only process emails to your address
    if (message.to !== targetEmail) {
      message.setReject("Invalid recipient");
      return;
    }

    const fromAddress = message.from.toLowerCase();
    const fromDomain = fromAddress.split("@")[1];
    
    // 1. Block spoofing from your own domain
    if (fromDomain === "ooheynerds.com") {
      const returnPath = message.headers.get("Return-Path") || "";
      if (!returnPath.includes("ooheynerds.com")) {
        message.setReject("Domain spoofing detected");
        console.log(`Blocked spoofing: ${fromAddress}`);
        return;
      }
    }

    // 2. Trusted senders - bypass all checks
    const allowList = [
      // Add trusted emails here
      // "trusted@example.com",
    ];

    if (allowList.includes(fromAddress)) {
      await message.forward(forwardTo);
      return;
    }

    // 3. Check SPF/DKIM
    const spf = message.headers.get("Received-SPF") || "";
    const authResults = message.headers.get("Authentication-Results") || "";
    
    if (spf.includes("fail") || authResults.includes("dkim=fail")) {
      message.setReject("Authentication failed");
      console.log(`Blocked failed auth: ${fromAddress}`);
      return;
    }

    // 4. Blocked domains
    const blockedDomains = [
      "0815.ru",
      "10minutemail.com",
      "guerrillamail.com",
      // Add more spam domains as you encounter them
    ];

    if (blockedDomains.some(domain => fromAddress.includes(domain))) {
      message.setReject("Blocked domain");
      return;
    }

    // 5. Subject line spam checks
    const subject = (message.headers.get("Subject") || "").toLowerCase();
    const spamPhrases = [
      "casino",
      "viagra", 
      "lottery",
      "winner",
      "congratulations",
      "click here",
      "limited time",
      "act now",
      "free money"
    ];

    const subjectSpamCount = spamPhrases.filter(phrase => subject.includes(phrase)).length;
    if (subjectSpamCount >= 2) {
      message.setReject("Spam detected");
      console.log(`Blocked spam subject: ${subject}`);
      return;
    }

    // 6. Check for suspicious headers
    const replyTo = message.headers.get("Reply-To") || "";
    const precedence = message.headers.get("Precedence") || "";
    
    // Different Reply-To is suspicious
    if (replyTo && replyTo !== message.from && !replyTo.includes(fromDomain)) {
      message.setReject("Suspicious headers");
      return;
    }
    
    // Bulk mail headers
    if (precedence.includes("bulk") || precedence.includes("junk")) {
      message.setReject("Bulk mail");
      return;
    }

    // 7. Check for excessive recipients
    const cc = message.headers.get("Cc") || "";
    if (cc && cc.split(",").length > 10) {
      message.setReject("Too many recipients");
      return;
    }

    // Email passed all checks - forward it
    await message.forward(forwardTo);
    console.log(`Forwarded: ${fromAddress}`);
  },
};