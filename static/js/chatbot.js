// Security Chatbot JavaScript
class SecurityChatbot {
    constructor() {
        this.isOpen = false;
        this.messages = [];
        this.init();
    }

    init() {
        this.createChatWidget();
        this.bindEvents();
        this.addWelcomeMessage();
    }

    createChatWidget() {
        const chatHTML = `
            <div id="security-chatbot" class="chatbot-container">
                <!-- Chatbot Toggle Button -->
                <div id="chatbot-toggle" class="chatbot-toggle">
                    <i class="bi bi-chat-dots"></i>
                    <span class="notification-badge">1</span>
                </div>

                <!-- Chatbot Window -->
                <div id="chatbot-window" class="chatbot-window">
                    <div class="chatbot-header">
                        <div class="d-flex align-items-center">
                            <i class="bi bi-robot me-2"></i>
                            <div>
                                <h6 class="mb-0">Security Assistant</h6>
                                <small class="text-muted">Ask me about security findings</small>
                            </div>
                        </div>
                        <button id="chatbot-close" class="btn-close btn-close-white"></button>
                    </div>
                    
                    <div class="chatbot-messages" id="chatbot-messages">
                        <!-- Messages will be added here -->
                    </div>
                    
                    <div class="chatbot-input">
                        <div class="input-group">
                            <input type="text" id="chatbot-input" class="form-control" 
                                   placeholder="Ask about security findings..." maxlength="500">
                            <button id="chatbot-send" class="btn btn-primary">
                                <i class="bi bi-send"></i>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', chatHTML);
    }

    bindEvents() {
        document.getElementById('chatbot-toggle').addEventListener('click', () => this.toggleChat());
        document.getElementById('chatbot-close').addEventListener('click', () => this.closeChat());
        document.getElementById('chatbot-send').addEventListener('click', () => this.sendMessage());
        document.getElementById('chatbot-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.sendMessage();
        });
    }

    toggleChat() {
        this.isOpen = !this.isOpen;
        const window = document.getElementById('chatbot-window');
        const toggle = document.getElementById('chatbot-toggle');
        
        if (this.isOpen) {
            window.style.display = 'flex';
            toggle.querySelector('.notification-badge').style.display = 'none';
            setTimeout(() => document.getElementById('chatbot-input').focus(), 100);
        } else {
            window.style.display = 'none';
        }
    }

    closeChat() {
        this.isOpen = false;
        document.getElementById('chatbot-window').style.display = 'none';
    }

    addWelcomeMessage() {
        this.addMessage("Hi! I'm your Security Assistant. I can help explain your scan results, security recommendations, and answer questions about web security. Try asking me about:", 'bot');
        
        setTimeout(() => {
            this.addMessage("• What are security headers?\n• How to fix missing CSRF protection?\n• Explain my cookie security findings\n• What's the risk level of my scan?", 'bot');
        }, 1000);
    }

    sendMessage() {
        const input = document.getElementById('chatbot-input');
        const message = input.value.trim();
        
        if (!message) return;
        
        this.addMessage(message, 'user');
        input.value = '';
        
        // Show typing indicator
        this.showTypingIndicator();
        
        // Simulate response delay
        setTimeout(() => {
            this.hideTypingIndicator();
            this.generateResponse(message);
        }, 1000 + Math.random() * 1000);
    }

    addMessage(text, sender) {
        const messagesContainer = document.getElementById('chatbot-messages');
        const messageDiv = document.createElement('div');
        messageDiv.className = `chatbot-message ${sender}`;
        
        const avatar = sender === 'bot' ? '<i class="bi bi-robot"></i>' : '<i class="bi bi-person"></i>';
        
        messageDiv.innerHTML = `
            <div class="message-avatar">${avatar}</div>
            <div class="message-content">
                <div class="message-text">${this.formatMessage(text)}</div>
                <div class="message-time">${new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</div>
            </div>
        `;
        
        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    formatMessage(text) {
        // Convert line breaks and format text
        return text.replace(/\n/g, '<br>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    }

    showTypingIndicator() {
        const messagesContainer = document.getElementById('chatbot-messages');
        const typingDiv = document.createElement('div');
        typingDiv.id = 'typing-indicator';
        typingDiv.className = 'chatbot-message bot typing';
        typingDiv.innerHTML = `
            <div class="message-avatar"><i class="bi bi-robot"></i></div>
            <div class="message-content">
                <div class="typing-dots">
                    <span></span><span></span><span></span>
                </div>
            </div>
        `;
        messagesContainer.appendChild(typingDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    hideTypingIndicator() {
        const typingIndicator = document.getElementById('typing-indicator');
        if (typingIndicator) typingIndicator.remove();
    }

    generateResponse(message) {
        const lowerMessage = message.toLowerCase();
        let response = '';

        // Security Headers responses
        if (lowerMessage.includes('security header') || lowerMessage.includes('headers')) {
            response = "**Security Headers** protect your website from various attacks:\n\n• **Content-Security-Policy**: Prevents XSS attacks\n• **X-Frame-Options**: Prevents clickjacking\n• **X-Content-Type-Options**: Prevents MIME sniffing\n• **Strict-Transport-Security**: Enforces HTTPS\n\nMissing headers indicate potential vulnerabilities that should be fixed.";
        }
        // CSRF responses
        else if (lowerMessage.includes('csrf') || lowerMessage.includes('cross-site request')) {
            response = "**CSRF (Cross-Site Request Forgery)** protection prevents malicious websites from performing actions on behalf of authenticated users.\n\n**To fix missing CSRF protection:**\n• Add CSRF tokens to all forms\n• Validate tokens on the server\n• Use SameSite cookie attributes\n• Implement proper referrer checking";
        }
        // Cookie security responses
        else if (lowerMessage.includes('cookie') || lowerMessage.includes('httponly') || lowerMessage.includes('secure')) {
            response = "**Cookie Security Flags** protect sensitive data:\n\n• **Secure**: Cookies only sent over HTTPS\n• **HttpOnly**: Prevents JavaScript access\n• **SameSite**: Controls cross-site cookie behavior\n\n**Missing flags** expose cookies to theft and manipulation. Always set these flags for authentication cookies!";
        }
        // TLS/SSL responses
        else if (lowerMessage.includes('tls') || lowerMessage.includes('ssl') || lowerMessage.includes('certificate')) {
            response = "**TLS/SSL Certificates** encrypt data between users and your server.\n\n**Key points:**\n• Certificates should not expire soon (<30 days = critical)\n• Use TLS 1.2 or higher\n• Ensure proper certificate chain\n• Monitor expiration dates regularly";
        }
        // Vulnerability responses
        else if (lowerMessage.includes('sql injection') || lowerMessage.includes('sqli')) {
            response = "**SQL Injection** allows attackers to manipulate database queries.\n\n**Prevention:**\n• Use parameterized queries\n• Input validation and sanitization\n• Principle of least privilege for DB users\n• Web Application Firewalls (WAF)";
        }
        else if (lowerMessage.includes('xss') || lowerMessage.includes('cross-site scripting')) {
            response = "**Cross-Site Scripting (XSS)** injects malicious scripts into web pages.\n\n**Prevention:**\n• Output encoding/escaping\n• Content Security Policy (CSP)\n• Input validation\n• Use security-focused frameworks";
        }
        // Risk level responses
        else if (lowerMessage.includes('risk') || lowerMessage.includes('priority') || lowerMessage.includes('fix first')) {
            response = "**Security Priority Order:**\n\n🔴 **Critical**: Active vulnerabilities (SQL injection, XSS)\n🟠 **High**: Missing security headers, weak TLS\n🟡 **Medium**: CSRF protection, cookie flags\n🟢 **Low**: Information disclosure, robots.txt\n\n**Fix critical issues first!**";
        }
        // General help
        else if (lowerMessage.includes('help') || lowerMessage.includes('what can you do')) {
            response = "I can help you with:\n\n• **Explaining scan results** and security findings\n• **Risk prioritization** and remediation advice\n• **Security best practices** and implementation\n• **Specific vulnerability** explanations\n\nJust ask me about any security topic or scan result!";
        }
        // Default response
        else {
            response = "I'd be happy to help with that security question! Try asking me about:\n\n• Security headers and their purpose\n• How to fix vulnerabilities\n• Cookie security settings\n• TLS/SSL certificate issues\n• Risk prioritization\n\nOr be more specific about what you'd like to know!";
        }

        this.addMessage(response, 'bot');
    }
}

// Initialize chatbot when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    new SecurityChatbot();
});
