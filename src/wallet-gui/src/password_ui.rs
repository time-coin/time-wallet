//! Password Prompt UI Module
//!
//! SECURITY: Provides password entry UI for wallet encryption
//! Features: Password strength indicator, confirmation, show/hide toggle

use eframe::egui;
use zeroize::Zeroize;

/// Password strength level
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PasswordStrength {
    VeryWeak,
    Weak,
    Medium,
    Strong,
    VeryStrong,
}

impl PasswordStrength {
    /// Calculate password strength based on criteria
    pub fn calculate(password: &str) -> Self {
        let len = password.len();
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        let mut score = 0;
        if len >= 8 {
            score += 1;
        }
        if len >= 12 {
            score += 1;
        }
        if has_lowercase {
            score += 1;
        }
        if has_uppercase {
            score += 1;
        }
        if has_digit {
            score += 1;
        }
        if has_special {
            score += 1;
        }

        match score {
            0..=1 => PasswordStrength::VeryWeak,
            2 => PasswordStrength::Weak,
            3 => PasswordStrength::Medium,
            4..=5 => PasswordStrength::Strong,
            _ => PasswordStrength::VeryStrong,
        }
    }

    /// Get color for strength indicator
    pub fn color(&self) -> egui::Color32 {
        match self {
            PasswordStrength::VeryWeak => egui::Color32::from_rgb(200, 0, 0),
            PasswordStrength::Weak => egui::Color32::from_rgb(255, 100, 0),
            PasswordStrength::Medium => egui::Color32::from_rgb(255, 200, 0),
            PasswordStrength::Strong => egui::Color32::from_rgb(100, 200, 0),
            PasswordStrength::VeryStrong => egui::Color32::from_rgb(0, 200, 0),
        }
    }

    /// Get label for strength
    pub fn label(&self) -> &'static str {
        match self {
            PasswordStrength::VeryWeak => "Very Weak",
            PasswordStrength::Weak => "Weak",
            PasswordStrength::Medium => "Medium",
            PasswordStrength::Strong => "Strong",
            PasswordStrength::VeryStrong => "Very Strong",
        }
    }
}

/// Password prompt dialog state
pub struct PasswordPrompt {
    /// Password input
    password: String,
    /// Confirmation password input
    confirm_password: String,
    /// Show password as text (not masked)
    show_password: bool,
    /// Whether this is a confirmation prompt (existing wallet)
    is_confirmation_only: bool,
    /// Error message
    error_message: Option<String>,
    /// Title of the dialog
    title: String,
    /// Whether the dialog is open
    pub is_open: bool,
    /// Whether user confirmed (Ok button clicked)
    pub confirmed: bool,
}

impl Default for PasswordPrompt {
    fn default() -> Self {
        Self::new("Enter Password")
    }
}

impl PasswordPrompt {
    /// Create a new password prompt for setting password
    pub fn new(title: &str) -> Self {
        Self {
            password: String::new(),
            confirm_password: String::new(),
            show_password: false,
            is_confirmation_only: false,
            error_message: None,
            title: title.to_string(),
            is_open: true,
            confirmed: false,
        }
    }

    /// Create a password prompt for unlocking (no confirmation)
    pub fn new_unlock(title: &str) -> Self {
        Self {
            password: String::new(),
            confirm_password: String::new(),
            show_password: false,
            is_confirmation_only: true,
            error_message: None,
            title: title.to_string(),
            is_open: true,
            confirmed: false,
        }
    }

    /// Show the password prompt dialog
    pub fn show(&mut self, ctx: &egui::Context) {
        if !self.is_open {
            return;
        }

        egui::Window::new(&self.title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(400.0);

                // Password input
                let mut submit_on_enter = false;
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.add_space(10.0);
                    let password_response = if self.show_password {
                        ui.text_edit_singleline(&mut self.password)
                    } else {
                        ui.add(egui::TextEdit::singleline(&mut self.password).password(true))
                    };

                    // Auto-focus on first show
                    if self.password.is_empty() && self.confirm_password.is_empty() {
                        password_response.request_focus();
                    }

                    // Check for Enter key press
                    if password_response.lost_focus()
                        && ui.input(|i| i.key_pressed(egui::Key::Enter))
                        && self.is_confirmation_only
                    {
                        submit_on_enter = true;
                    }
                });

                // Show password toggle
                ui.checkbox(&mut self.show_password, "Show password");

                // Password strength indicator (only when setting new password)
                if !self.is_confirmation_only && !self.password.is_empty() {
                    let strength = PasswordStrength::calculate(&self.password);
                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        ui.label("Strength:");
                        ui.add_space(5.0);
                        ui.colored_label(strength.color(), strength.label());
                    });

                    // Strength bar
                    let progress = match strength {
                        PasswordStrength::VeryWeak => 0.2,
                        PasswordStrength::Weak => 0.4,
                        PasswordStrength::Medium => 0.6,
                        PasswordStrength::Strong => 0.8,
                        PasswordStrength::VeryStrong => 1.0,
                    };
                    ui.add(egui::ProgressBar::new(progress).fill(strength.color()));
                }

                // Confirmation password (only when setting new password)
                if !self.is_confirmation_only {
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label("Confirm:");
                        ui.add_space(17.0);
                        let confirm_response = if self.show_password {
                            ui.text_edit_singleline(&mut self.confirm_password)
                        } else {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.confirm_password)
                                    .password(true),
                            )
                        };

                        // Check for Enter key press on confirm field
                        if confirm_response.lost_focus()
                            && ui.input(|i| i.key_pressed(egui::Key::Enter))
                        {
                            submit_on_enter = true;
                        }
                    });
                }

                // Error message
                if let Some(error) = &self.error_message {
                    ui.add_space(10.0);
                    ui.colored_label(egui::Color32::RED, format!("⚠ {}", error));
                }

                // Password requirements
                if !self.is_confirmation_only {
                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(5.0);
                    ui.label("Password requirements:");
                    ui.label("  • At least 8 characters");
                    ui.label("  • Mix of uppercase and lowercase");
                    ui.label("  • At least one number");
                    ui.label("  • Special characters recommended");
                }

                ui.add_space(15.0);
                ui.separator();
                ui.add_space(10.0);

                // Buttons
                ui.horizontal(|ui| {
                    // OK button
                    let ok_enabled = if self.is_confirmation_only {
                        !self.password.is_empty()
                    } else {
                        !self.password.is_empty()
                            && !self.confirm_password.is_empty()
                            && self.password.len() >= 8
                    };

                    // Handle Enter key submission or button click
                    if (submit_on_enter && ok_enabled)
                        || ui
                            .add_enabled(ok_enabled, egui::Button::new("OK"))
                            .clicked()
                    {
                        if self.is_confirmation_only {
                            // Just confirm password
                            self.confirmed = true;
                            self.is_open = false;
                        } else {
                            // Validate password match
                            if self.password != self.confirm_password {
                                self.error_message = Some("Passwords do not match".to_string());
                            } else if self.password.len() < 8 {
                                self.error_message =
                                    Some("Password must be at least 8 characters".to_string());
                            } else {
                                self.confirmed = true;
                                self.is_open = false;
                            }
                        }
                    }

                    ui.add_space(10.0);

                    // Cancel button
                    if ui.button("Cancel").clicked() {
                        self.confirmed = false;
                        self.is_open = false;
                        // Zero password from memory
                        self.password.zeroize();
                        self.confirm_password.zeroize();
                    }
                });
            });
    }

    /// Get the password (moves ownership, clears internal storage)
    pub fn take_password(&mut self) -> String {
        let password = std::mem::take(&mut self.password);
        self.confirm_password.zeroize();
        password
    }

    /// Reset the dialog state
    pub fn reset(&mut self) {
        self.password.zeroize();
        self.confirm_password.zeroize();
        self.show_password = false;
        self.error_message = None;
        self.confirmed = false;
        self.is_open = false;
    }

    /// Check if password was confirmed
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// Check if dialog is open
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// Open the dialog
    pub fn open(&mut self) {
        self.is_open = true;
        self.confirmed = false;
        self.error_message = None;
    }
}

impl Drop for PasswordPrompt {
    fn drop(&mut self) {
        // Ensure passwords are zeroized when dropped
        self.password.zeroize();
        self.confirm_password.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_strength_calculation() {
        assert_eq!(
            PasswordStrength::calculate("123"),
            PasswordStrength::VeryWeak
        );
        assert_eq!(
            PasswordStrength::calculate("password"),
            PasswordStrength::Weak
        );
        assert_eq!(
            PasswordStrength::calculate("Password1"),
            PasswordStrength::Strong // 9 chars, upper, lower, digit = 4 points
        );
        assert_eq!(
            PasswordStrength::calculate("Password123"),
            PasswordStrength::Strong // 11 chars, upper, lower, digit = 4 points
        );
        assert_eq!(
            PasswordStrength::calculate("P@ssw0rd123!"),
            PasswordStrength::VeryStrong // 12+ chars, upper, lower, digit, special = 6 points
        );
    }

    #[test]
    fn test_password_prompt_creation() {
        let prompt = PasswordPrompt::new("Test");
        assert!(!prompt.is_confirmation_only);
        assert!(!prompt.confirmed);
        assert!(prompt.is_open);
    }

    #[test]
    fn test_password_prompt_unlock() {
        let prompt = PasswordPrompt::new_unlock("Unlock");
        assert!(prompt.is_confirmation_only);
        assert!(!prompt.confirmed);
    }
}
