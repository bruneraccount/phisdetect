/**
 * faq.js — FAQ Manager (Help Page)
 * PhisDetect — Terminal Dashboard
 */

const FaqManager = {
    /**
     * Initialize FAQ
     */
    init() {
        this.setupCategories();
        this.setupAccordion();
    },

    /**
     * Setup category filter buttons
     */
    setupCategories() {
        const buttons = document.querySelectorAll('.category-btn');
        buttons.forEach(btn => {
            btn.addEventListener('click', () => {
                // Update active state
                buttons.forEach(b => {
                    b.classList.remove('active');
                    b.setAttribute('aria-selected', 'false');
                });
                btn.classList.add('active');
                btn.setAttribute('aria-selected', 'true');

                // Filter FAQs
                const category = btn.dataset.category;
                this.filterFaqs(category);
            });
        });
    },

    /**
     * Filter FAQs by category
     */
    filterFaqs(category) {
        const faqs = document.querySelectorAll('.faq-item');
        let visibleCount = 0;

        faqs.forEach(faq => {
            const faqCategory = faq.dataset.category;
            if (category === 'all' || faqCategory === category) {
                faq.classList.remove('hidden');
                visibleCount++;
            } else {
                faq.classList.add('hidden');
                // Close hidden FAQs
                faq.classList.remove('active');
                const question = faq.querySelector('.faq-question');
                if (question) {
                    question.setAttribute('aria-expanded', 'false');
                }
            }
        });

        // If no visible FAQs, show a message
        const container = document.querySelector('.faq-accordion');
        const existingMsg = container?.querySelector('.no-faqs-message');
        
        if (visibleCount === 0) {
            if (!existingMsg) {
                const msg = document.createElement('div');
                msg.className = 'no-faqs-message';
                msg.style.cssText = `
                    text-align: center;
                    padding: 40px 20px;
                    color: var(--text-muted);
                    background: var(--bg-card);
                    border-radius: var(--radius-md);
                    border: 1px solid var(--border-subtle);
                `;
                msg.innerHTML = `
                    <i class="fa-regular fa-circle-question" style="font-size: 32px; display: block; margin-bottom: 12px; opacity: 0.4;"></i>
                    <p style="font-size: 14px;">No FAQs found in this category.</p>
                `;
                container?.appendChild(msg);
            }
        } else {
            if (existingMsg) {
                existingMsg.remove();
            }
        }
    },

    /**
     * Setup accordion toggle for FAQ items
     */
    setupAccordion() {
        // Use event delegation for better performance
        document.addEventListener('click', (e) => {
            const question = e.target.closest('.faq-question');
            if (question) {
                this.toggleFaq(question);
            }
        });

        // Keyboard support: Enter and Space
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                const question = e.target.closest('.faq-question');
                if (question) {
                    e.preventDefault();
                    this.toggleFaq(question);
                }
            }
        });
    },

    /**
     * Toggle a single FAQ item
     */
    toggleFaq(questionElement) {
        const faqItem = questionElement.closest('.faq-item');
        if (!faqItem) return;

        // Check if it's already active
        const isActive = faqItem.classList.contains('active');

        // Toggle this one
        if (isActive) {
            faqItem.classList.remove('active');
            questionElement.setAttribute('aria-expanded', 'false');
        } else {
            faqItem.classList.add('active');
            questionElement.setAttribute('aria-expanded', 'true');
        }
    },

    /**
     * Get all FAQ items as data (for search/export)
     */
    getAllFaqs() {
        const faqs = document.querySelectorAll('.faq-item');
        return Array.from(faqs).map(faq => {
            const question = faq.querySelector('.faq-question-text')?.textContent?.trim() || '';
            const answer = faq.querySelector('.faq-answer')?.textContent?.trim() || '';
            const category = faq.dataset.category || 'general';
            return { question, answer, category };
        });
    },

    /**
     * Search FAQs (simple client-side search)
     */
    searchFaqs(query) {
        if (!query || query.length < 2) {
            // Show all
            this.filterFaqs('all');
            // Reset category buttons
            document.querySelectorAll('.category-btn').forEach(btn => {
                btn.classList.remove('active');
                if (btn.dataset.category === 'all') {
                    btn.classList.add('active');
                    btn.setAttribute('aria-selected', 'true');
                } else {
                    btn.setAttribute('aria-selected', 'false');
                }
            });
            return;
        }

        const searchLower = query.toLowerCase();
        const faqs = document.querySelectorAll('.faq-item');

        faqs.forEach(faq => {
            const question = faq.querySelector('.faq-question-text')?.textContent?.toLowerCase() || '';
            const answer = faq.querySelector('.faq-answer')?.textContent?.toLowerCase() || '';
            
            if (question.includes(searchLower) || answer.includes(searchLower)) {
                faq.classList.remove('hidden');
                // Expand matching FAQs
                faq.classList.add('active');
                const q = faq.querySelector('.faq-question');
                if (q) q.setAttribute('aria-expanded', 'true');
            } else {
                faq.classList.add('hidden');
                faq.classList.remove('active');
                const q = faq.querySelector('.faq-question');
                if (q) q.setAttribute('aria-expanded', 'false');
            }
        });

        // Show message if no results
        const visible = document.querySelectorAll('.faq-item:not(.hidden)');
        const container = document.querySelector('.faq-accordion');
        const existingMsg = container?.querySelector('.no-faqs-message');
        
        if (visible.length === 0) {
            if (!existingMsg) {
                const msg = document.createElement('div');
                msg.className = 'no-faqs-message';
                msg.style.cssText = `
                    text-align: center;
                    padding: 40px 20px;
                    color: var(--text-muted);
                    background: var(--bg-card);
                    border-radius: var(--radius-md);
                    border: 1px solid var(--border-subtle);
                `;
                msg.innerHTML = `
                    <i class="fa-regular fa-search" style="font-size: 32px; display: block; margin-bottom: 12px; opacity: 0.4;"></i>
                    <p style="font-size: 14px;">No FAQs found matching "<strong>${query}</strong>".</p>
                `;
                container?.appendChild(msg);
            } else {
                const msgText = existingMsg.querySelector('p');
                if (msgText) {
                    msgText.innerHTML = `No FAQs found matching "<strong>${query}</strong>".`;
                }
            }
        } else {
            if (existingMsg) {
                existingMsg.remove();
            }
        }
    }
};

// Export for use in other modules
window.FaqManager = FaqManager;

// Also expose toggle function globally for inline onclick
window.toggleFaq = function(element) {
    FaqManager.toggleFaq(element);
};