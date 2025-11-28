// static/js/app.js
// BarbLab - Sistema de Agendamento
// Versão 2.0 - Melhorado

(() => {
  'use strict';

  // ============================================================
  // CONFIGURAÇÕES
  // ============================================================
  
  const CONFIG = {
    redirectDelay: 800,
    debounceDelay: 300,
    toastDuration: 4000,
    passwordMinLength: 6,
    endpoints: {
      register: '/api/register',
      login: '/api/login',
      logout: '/api/logout',
      me: '/api/me',
      updateMe: '/api/me',
      changePassword: '/api/me/password',
      validarCpf: '/api/validar-cpf',
      validarEmail: '/api/validar-email',
      buscarCep: '/api/buscar-cep',
      servicos: '/api/servicos',
      barbeiros: '/api/barbeiros',
      horariosDisponiveis: '/api/horarios-disponiveis',
      agendar: '/api/agendar',
      meusAgendamentos: '/api/meus-agendamentos',
      cancelarAgendamento: '/api/agendamento/{id}/cancelar'
    }
  };

  // ============================================================
  // UTILIDADES
  // ============================================================

  const Utils = {
    // Apenas dígitos
    onlyDigits: (s) => (s || '').replace(/\D/g, ''),

    // Debounce
    debounce: (fn, delay = CONFIG.debounceDelay) => {
      let timer;
      return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), delay);
      };
    },

    // Formata data para exibição
    formatDate: (dateStr) => {
      if (!dateStr) return '';
      const date = new Date(dateStr + 'T00:00:00');
      return date.toLocaleDateString('pt-BR');
    },

    // Formata data e hora
    formatDateTime: (dateStr) => {
      if (!dateStr) return '';
      const date = new Date(dateStr);
      return date.toLocaleString('pt-BR');
    },

    // Capitaliza primeira letra
    capitalize: (str) => {
      if (!str) return '';
      return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
    },

    // Pega primeiro nome
    firstName: (fullName) => {
      if (!fullName) return '';
      return fullName.split(' ')[0];
    },

    // Scroll suave para elemento
    scrollTo: (element) => {
      if (element) {
        element.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    },

    // Verifica se é mobile
    isMobile: () => window.innerWidth <= 768,

    // Gera ID único
    uniqueId: () => '_' + Math.random().toString(36).substr(2, 9)
  };

  // ============================================================
  // MÁSCARAS
  // ============================================================

  const Masks = {
    cpf: (value) => {
      return Utils.onlyDigits(value)
        .replace(/(\d{3})(\d)/, '$1.$2')
        .replace(/(\d{3})(\d)/, '$1.$2')
        .replace(/(\d{3})(\d{1,2})$/, '$1-$2')
        .substring(0, 14);
    },

    phone: (value) => {
      const digits = Utils.onlyDigits(value);
      if (digits.length <= 10) {
        return digits
          .replace(/(\d{2})(\d)/, '($1) $2')
          .replace(/(\d{4})(\d)/, '$1-$2')
          .substring(0, 14);
      }
      return digits
        .replace(/(\d{2})(\d)/, '($1) $2')
        .replace(/(\d{5})(\d)/, '$1-$2')
        .substring(0, 15);
    },

    cep: (value) => {
      return Utils.onlyDigits(value)
        .replace(/(\d{5})(\d)/, '$1-$2')
        .substring(0, 9);
    },

    date: (value) => {
      return Utils.onlyDigits(value)
        .replace(/(\d{2})(\d)/, '$1/$2')
        .replace(/(\d{2})(\d)/, '$1/$2')
        .substring(0, 10);
    },

    // Aplica máscara a um input
    apply: (input, maskFn) => {
      if (!input) return;
      input.addEventListener('input', (e) => {
        const cursorPos = e.target.selectionStart;
        const oldLength = e.target.value.length;
        e.target.value = maskFn(e.target.value);
        const newLength = e.target.value.length;
        const newPos = cursorPos + (newLength - oldLength);
        e.target.setSelectionRange(newPos, newPos);
      });
    }
  };

  // ============================================================
  // VALIDAÇÕES
  // ============================================================

  const Validators = {
    // Valida CPF
    cpf: (cpf) => {
      cpf = Utils.onlyDigits(cpf);
      
      if (cpf.length !== 11) return false;
      if (/^(\d)\1+$/.test(cpf)) return false;

      const calcDigit = (size) => {
        let sum = 0;
        for (let i = 0; i < size; i++) {
          sum += parseInt(cpf[i]) * (size + 1 - i);
        }
        const remainder = 11 - (sum % 11);
        return remainder >= 10 ? 0 : remainder;
      };

      return calcDigit(9) === parseInt(cpf[9]) && 
             calcDigit(10) === parseInt(cpf[10]);
    },

    // Valida e-mail
    email: (email) => {
      if (!email) return true; // Opcional
      const pattern = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
      return pattern.test(email.toLowerCase().trim());
    },

    // Valida telefone
    phone: (phone) => {
      if (!phone) return true; // Opcional
      const digits = Utils.onlyDigits(phone);
      return digits.length >= 10 && digits.length <= 11;
    },

    // Valida CEP
    cep: (cep) => {
      if (!cep) return true; // Opcional
      return Utils.onlyDigits(cep).length === 8;
    },

    // Valida senha
    password: (password) => {
      return password && password.length >= CONFIG.passwordMinLength;
    },

    // Valida nome
    name: (name) => {
      return name && name.trim().length >= 3;
    },

    // Força da senha
    passwordStrength: (password) => {
      if (!password) return { score: 0, label: 'Muito fraca', class: 'weak' };
      
      let score = 0;
      
      // Comprimento
      if (password.length >= 6) score++;
      if (password.length >= 8) score++;
      if (password.length >= 12) score++;
      
      // Complexidade
      if (/[a-z]/.test(password)) score++;
      if (/[A-Z]/.test(password)) score++;
      if (/[0-9]/.test(password)) score++;
      if (/[^a-zA-Z0-9]/.test(password)) score++;

      if (score <= 2) return { score, label: 'Fraca', class: 'weak' };
      if (score <= 4) return { score, label: 'Média', class: 'medium' };
      if (score <= 6) return { score, label: 'Forte', class: 'strong' };
      return { score, label: 'Muito forte', class: 'very-strong' };
    }
  };

  // ============================================================
  // API CLIENT
  // ============================================================

  const API = {
    // Requisição base
    async request(url, options = {}) {
      const defaultOptions = {
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'same-origin'
      };

      const config = { ...defaultOptions, ...options };
      
      if (config.body && typeof config.body === 'object') {
        config.body = JSON.stringify(config.body);
      }

      try {
        const response = await fetch(url, config);
        const data = await response.json().catch(() => ({}));
        
        return {
          ok: response.ok,
          status: response.status,
          data
        };
      } catch (error) {
        console.error('API Error:', error);
        return {
          ok: false,
          status: 0,
          data: { error: 'Erro de conexão. Verifique sua internet.' }
        };
      }
    },

    // GET
    get(url, params = {}) {
      const queryString = new URLSearchParams(params).toString();
      const fullUrl = queryString ? `${url}?${queryString}` : url;
      return this.request(fullUrl);
    },

    // POST
    post(url, body = {}) {
      return this.request(url, { method: 'POST', body });
    },

    // PUT
    put(url, body = {}) {
      return this.request(url, { method: 'PUT', body });
    },

    // DELETE
    delete(url) {
      return this.request(url, { method: 'DELETE' });
    }
  };

  // ============================================================
  // TOAST NOTIFICATIONS
  // ============================================================

  const Toast = {
    container: null,

    init() {
      if (this.container) return;
      
      this.container = document.createElement('div');
      this.container.id = 'toast-container';
      this.container.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 10000;
        display: flex;
        flex-direction: column;
        gap: 10px;
        max-width: 400px;
      `;
      document.body.appendChild(this.container);
    },

    show(message, type = 'info', duration = CONFIG.toastDuration) {
      this.init();

      const toast = document.createElement('div');
      toast.className = `toast toast-${type}`;
      
      const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
      };

      const colors = {
        success: { bg: '#27ae60', border: '#2ecc71' },
        error: { bg: '#c0392b', border: '#e74c3c' },
        warning: { bg: '#d35400', border: '#e67e22' },
        info: { bg: '#2980b9', border: '#3498db' }
      };

      const color = colors[type] || colors.info;

      toast.style.cssText = `
        background: ${color.bg};
        border-left: 4px solid ${color.border};
        color: white;
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        display: flex;
        align-items: center;
        gap: 12px;
        animation: slideIn 0.3s ease;
        cursor: pointer;
      `;

      toast.innerHTML = `
        <span style="font-size: 1.2em;">${icons[type]}</span>
        <span style="flex: 1;">${message}</span>
        <span style="opacity: 0.7; font-size: 1.2em;">&times;</span>
      `;

      // Adiciona animação CSS
      if (!document.getElementById('toast-styles')) {
        const style = document.createElement('style');
        style.id = 'toast-styles';
        style.textContent = `
          @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
          }
          @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
          }
        `;
        document.head.appendChild(style);
      }

      this.container.appendChild(toast);

      const remove = () => {
        toast.style.animation = 'slideOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
      };

      toast.addEventListener('click', remove);
      
      if (duration > 0) {
        setTimeout(remove, duration);
      }

      return toast;
    },

    success(message, duration) { return this.show(message, 'success', duration); },
    error(message, duration) { return this.show(message, 'error', duration); },
    warning(message, duration) { return this.show(message, 'warning', duration); },
    info(message, duration) { return this.show(message, 'info', duration); }
  };

  // ============================================================
  // LOADING STATES
  // ============================================================

  const Loading = {
    // Mostra loading em botão
    button(btn, loading = true) {
      if (!btn) return;

      if (loading) {
        btn.disabled = true;
        btn.dataset.originalText = btn.innerHTML;
        btn.innerHTML = `
          <span class="spinner"></span>
          <span>Aguarde...</span>
        `;
        btn.style.opacity = '0.7';
      } else {
        btn.disabled = false;
        btn.innerHTML = btn.dataset.originalText || btn.innerHTML;
        btn.style.opacity = '1';
      }
    },

    // Mostra loading global
    global(show = true) {
      let overlay = document.getElementById('loading-overlay');
      
      if (show) {
        if (!overlay) {
          overlay = document.createElement('div');
          overlay.id = 'loading-overlay';
          overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
          `;
          overlay.innerHTML = `
            <div style="text-align: center; color: white;">
              <div class="spinner" style="width: 50px; height: 50px; margin: 0 auto 15px;"></div>
              <p>Carregando...</p>
            </div>
          `;
          document.body.appendChild(overlay);
        }
        overlay.style.display = 'flex';
      } else if (overlay) {
        overlay.style.display = 'none';
      }
    }
  };

  // Adiciona CSS do spinner
  if (!document.getElementById('spinner-styles')) {
    const style = document.createElement('style');
    style.id = 'spinner-styles';
    style.textContent = `
            .spinner {
        width: 20px;
        height: 20px;
        border: 3px solid rgba(255,255,255,0.3);
        border-top-color: #fff;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
        display: inline-block;
        vertical-align: middle;
      }
      @keyframes spin {
        to { transform: rotate(360deg); }
      }
    `;
    document.head.appendChild(style);
  }

  // ============================================================
  // FORM FEEDBACK
  // ============================================================

  const FormFeedback = {
    // Define estado do campo
    setState(input, state, message = '') {
      if (!input) return;

      const formGroup = input.closest('.form-group');
      if (!formGroup) return;

      // Remove estados anteriores
      formGroup.classList.remove('success', 'error', 'loading');
      
      // Adiciona novo estado
      if (state) {
        formGroup.classList.add(state);
      }

      // Atualiza mensagem de feedback
      const feedback = formGroup.querySelector('.feedback, small');
      if (feedback) {
        feedback.textContent = message;
        feedback.className = `feedback ${state || ''}`;
      }

      // Atualiza ícone de validação
      const icon = formGroup.querySelector('.validation-icon');
      if (icon) {
        icon.className = `validation-icon ${state || ''}`;
      }
    },

    success(input, message = '') {
      this.setState(input, 'success', message);
    },

    error(input, message = '') {
      this.setState(input, 'error', message);
    },

    loading(input, message = 'Verificando...') {
      this.setState(input, 'loading', message);
    },

    clear(input) {
      this.setState(input, null, '');
    },

    // Limpa todos os feedbacks do formulário
    clearAll(form) {
      if (!form) return;
      form.querySelectorAll('.form-group').forEach(group => {
        group.classList.remove('success', 'error', 'loading');
        const feedback = group.querySelector('.feedback, small');
        if (feedback) feedback.textContent = '';
      });
    }
  };

  // ============================================================
  // SERVIÇOS - CEP
  // ============================================================

  const CEPService = {
    cache: {},

    async buscar(cep) {
      cep = Utils.onlyDigits(cep);
      
      if (cep.length !== 8) {
        return { error: 'CEP deve ter 8 dígitos' };
      }

      // Verifica cache
      if (this.cache[cep]) {
        return this.cache[cep];
      }

      try {
        // Tenta primeiro pelo backend
        const response = await API.get(`${CONFIG.endpoints.buscarCep}/${cep}`);
        
        if (response.ok && response.data && !response.data.error) {
          this.cache[cep] = response.data;
          return response.data;
        }

        // Fallback para ViaCEP direto
        const viaCepResponse = await fetch(`https://viacep.com.br/ws/${cep}/json/`);
        const data = await viaCepResponse.json();

        if (data.erro) {
          return { error: 'CEP não encontrado' };
        }

        const result = {
          cep: data.cep?.replace('-', ''),
          logradouro: data.logradouro || '',
          bairro: data.bairro || '',
          cidade: data.localidade || '',
          estado: data.uf || '',
          endereco_completo: `${data.logradouro || ''}, ${data.bairro || ''} - ${data.localidade || ''}/${data.uf || ''}`
        };

        this.cache[cep] = result;
        return result;

      } catch (error) {
        console.error('Erro ao buscar CEP:', error);
        return { error: 'Erro ao buscar CEP' };
      }
    }
  };

  // ============================================================
  // MÓDULO DE CADASTRO
  // ============================================================

  const CadastroModule = {
    form: null,
    fields: {},
    submitBtn: null,

    init() {
      this.form = document.getElementById('cadastroForm');
      if (!this.form) return;

      console.log('Inicializando módulo de cadastro...');

      // Mapeia campos
      this.fields = {
        nome: document.getElementById('nome'),
        cpf: document.getElementById('cpf'),
        password: document.getElementById('password'),
        password2: document.getElementById('password2'),
        email: document.getElementById('email'),
        telefone: document.getElementById('telefone'),
        cep: document.getElementById('cep'),
        endereco: document.getElementById('endereco'),
        numero: document.getElementById('numero'),
        complemento: document.getElementById('complemento'),
        observacoes: document.getElementById('observacoes'),
        termos: document.getElementById('termos')
      };

      this.submitBtn = document.getElementById('btnCadastrar') || this.form.querySelector('button[type="submit"]');

      this.setupMasks();
      this.setupValidations();
      this.setupPasswordStrength();
      this.setupPasswordToggle();
      this.setupCEPAutofill();
      this.setupCharCounter();
      this.setupProgressBar();
      this.setupSubmit();
    },

    // Configura máscaras
    setupMasks() {
      Masks.apply(this.fields.cpf, Masks.cpf);
      Masks.apply(this.fields.telefone, Masks.phone);
      Masks.apply(this.fields.cep, Masks.cep);
    },

    // Configura validações em tempo real
    setupValidations() {
      const { cpf, email, telefone, nome, password, password2 } = this.fields;

      // Nome
      if (nome) {
        nome.addEventListener('blur', () => {
          if (!nome.value.trim()) {
            FormFeedback.error(nome, 'Nome é obrigatório');
          } else if (!Validators.name(nome.value)) {
            FormFeedback.error(nome, 'Nome deve ter pelo menos 3 caracteres');
          } else {
            FormFeedback.success(nome, '');
          }
          this.updateProgress();
        });
      }

      // CPF com validação assíncrona
      if (cpf) {
        cpf.addEventListener('blur', Utils.debounce(async () => {
          const value = cpf.value;
          
          if (!value) {
            FormFeedback.error(cpf, 'CPF é obrigatório');
            return;
          }

          if (!Validators.cpf(value)) {
            FormFeedback.error(cpf, 'CPF inválido');
            return;
          }

          // Verifica disponibilidade no servidor
          FormFeedback.loading(cpf, 'Verificando disponibilidade...');

          const response = await API.get(CONFIG.endpoints.validarCpf, { 
            cpf: Utils.onlyDigits(value) 
          });

          if (response.ok && response.data.valid) {
            FormFeedback.success(cpf, 'CPF disponível');
          } else {
            FormFeedback.error(cpf, response.data.message || 'CPF já cadastrado');
          }

          this.updateProgress();
        }, 500));
      }

      // E-mail com validação assíncrona
      if (email) {
        email.addEventListener('blur', Utils.debounce(async () => {
          const value = email.value.trim();
          
          if (!value) {
            FormFeedback.clear(email);
            return;
          }

          if (!Validators.email(value)) {
            FormFeedback.error(email, 'E-mail inválido');
            return;
          }

          // Verifica disponibilidade
          FormFeedback.loading(email, 'Verificando...');

          const response = await API.get(CONFIG.endpoints.validarEmail, { email: value });

          if (response.ok && response.data.valid) {
            FormFeedback.success(email, 'E-mail disponível');
          } else {
            FormFeedback.error(email, response.data.message || 'E-mail já cadastrado');
          }
        }, 500));
      }

      // Telefone
      if (telefone) {
        telefone.addEventListener('blur', () => {
          const value = telefone.value;
          if (value && !Validators.phone(value)) {
            FormFeedback.error(telefone, 'Telefone inválido');
          } else if (value) {
            FormFeedback.success(telefone, '');
          } else {
            FormFeedback.clear(telefone);
          }
        });
      }

      // Senha
      if (password) {
        password.addEventListener('input', () => {
          this.updatePasswordStrength();
          this.checkPasswordMatch();
          this.updateProgress();
        });

        password.addEventListener('blur', () => {
          if (!password.value) {
            FormFeedback.error(password, 'Senha é obrigatória');
          } else if (!Validators.password(password.value)) {
            FormFeedback.error(password, `Mínimo ${CONFIG.passwordMinLength} caracteres`);
          }
        });
      }

      // Confirmar senha
      if (password2) {
        password2.addEventListener('input', () => {
          this.checkPasswordMatch();
          this.updateProgress();
        });
      }
    },

    // Verifica se senhas coincidem
    checkPasswordMatch() {
      const { password, password2 } = this.fields;
      if (!password || !password2 || !password2.value) return;

      if (password.value !== password2.value) {
        FormFeedback.error(password2, 'Senhas não coincidem');
      } else {
        FormFeedback.success(password2, 'Senhas coincidem');
      }
    },

    // Indicador de força da senha
    setupPasswordStrength() {
      const strengthBar = document.getElementById('strengthFill');
      const strengthText = document.getElementById('strengthText');
      
      if (!strengthBar || !strengthText) return;

      this.strengthBar = strengthBar;
      this.strengthText = strengthText;
    },

    updatePasswordStrength() {
      if (!this.strengthBar || !this.fields.password) return;

      const strength = Validators.passwordStrength(this.fields.password.value);
      
      this.strengthBar.className = `strength-fill ${strength.class}`;
      this.strengthText.textContent = strength.label;

      // Atualiza largura baseado no score
      const widths = { 'weak': '25%', 'medium': '50%', 'strong': '75%', 'very-strong': '100%' };
      this.strengthBar.style.width = widths[strength.class] || '0%';
    },

    // Toggle mostrar/ocultar senha
    setupPasswordToggle() {
      document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
          const targetId = btn.dataset.target;
          const input = document.getElementById(targetId);
          
          if (!input) return;

          const isPassword = input.type === 'password';
          input.type = isPassword ? 'text' : 'password';
          
          const icon = btn.querySelector('i');
          if (icon) {
            icon.className = isPassword ? 'fas fa-eye-slash' : 'fas fa-eye';
          }
        });
      });
    },

    // Auto-preenchimento por CEP
    setupCEPAutofill() {
      const { cep, endereco, numero } = this.fields;
      if (!cep) return;

      cep.addEventListener('blur', Utils.debounce(async () => {
        const value = cep.value;
        
        if (!value || Utils.onlyDigits(value).length !== 8) {
          if (value) FormFeedback.error(cep, 'CEP inválido');
          return;
        }

        FormFeedback.loading(cep, 'Buscando endereço...');

        const data = await CEPService.buscar(value);

        if (data.error) {
          FormFeedback.error(cep, data.error);
        } else {
          FormFeedback.success(cep, `${data.cidade}/${data.estado}`);
          
          if (endereco) {
            endereco.value = data.endereco_completo || 
              `${data.logradouro}, ${data.bairro} - ${data.cidade}/${data.estado}`;
          }

          // Foca no campo número
          if (numero) {
            numero.focus();
          }
        }
      }, 300));
    },

    // Contador de caracteres
    setupCharCounter() {
      const { observacoes } = this.fields;
      const counter = document.getElementById('obsCounter');
      
      if (!observacoes || !counter) return;

      const maxLength = observacoes.maxLength || 500;

      observacoes.addEventListener('input', () => {
        const current = observacoes.value.length;
        counter.textContent = `${current} / ${maxLength} caracteres`;
        
        if (current >= maxLength * 0.9) {
          counter.style.color = '#e74c3c';
        } else {
          counter.style.color = '#888';
        }
      });
    },

    // Barra de progresso
    setupProgressBar() {
      this.progressFill = document.getElementById('progressFill');
      this.filledFieldsSpan = document.getElementById('filledFields');
      this.totalFieldsSpan = document.getElementById('totalFields');

      // Campos obrigatórios
      this.requiredFields = ['nome', 'cpf', 'password', 'password2', 'email'];
      
      if (this.totalFieldsSpan) {
        this.totalFieldsSpan.textContent = this.requiredFields.length;
      }

      // Atualiza ao digitar em qualquer campo obrigatório
      this.requiredFields.forEach(fieldName => {
        const field = this.fields[fieldName];
        if (field) {
          field.addEventListener('input', () => this.updateProgress());
        }
      });
    },

    updateProgress() {
      if (!this.progressFill) return;

      let filled = 0;
      
      this.requiredFields.forEach(fieldName => {
        const field = this.fields[fieldName];
        if (field && field.value.trim()) {
          filled++;
        }
      });

      const percentage = (filled / this.requiredFields.length) * 100;
      this.progressFill.style.width = `${percentage}%`;

      if (this.filledFieldsSpan) {
        this.filledFieldsSpan.textContent = filled;
      }
    },

    // Configura submit
    setupSubmit() {
      this.form.addEventListener('submit', async (e) => {
        e.preventDefault();
        await this.handleSubmit();
      });
    },

    // Valida todos os campos
    validateAll() {
      const errors = {};
      const { nome, cpf, password, password2, email, telefone, cep, termos } = this.fields;

      // Nome
      if (!nome?.value.trim()) {
        errors.nome = 'Nome é obrigatório';
      } else if (!Validators.name(nome.value)) {
        errors.nome = 'Nome deve ter pelo menos 3 caracteres';
      }
            // CPF
            if (!cpf?.value) {
              errors.cpf = 'CPF é obrigatório';
            } else if (!Validators.cpf(cpf.value)) {
              errors.cpf = 'CPF inválido';
            }
      
            // Senha
            if (!password?.value) {
              errors.password = 'Senha é obrigatória';
            } else if (!Validators.password(password.value)) {
              errors.password = `Mínimo ${CONFIG.passwordMinLength} caracteres`;
            }
      
            // Confirmar senha
            if (password?.value !== password2?.value) {
              errors.password2 = 'Senhas não coincidem';
            }
      
            // E-mail (opcional mas válido)
            if (email?.value && !Validators.email(email.value)) {
              errors.email = 'E-mail inválido';
            }
      
            // Telefone (opcional mas válido)
            if (telefone?.value && !Validators.phone(telefone.value)) {
              errors.telefone = 'Telefone inválido';
            }
      
            // Termos
            if (termos && !termos.checked) {
              errors.termos = 'Aceite os termos para continuar';
            }
      
            // Mostra erros nos campos
            Object.keys(errors).forEach(field => {
              if (this.fields[field]) {
                FormFeedback.error(this.fields[field], errors[field]);
              }
            });
      
            return Object.keys(errors).length === 0;
          },
      
          // Submit do formulário
          async handleSubmit() {
            if (!this.validateAll()) {
              Toast.error('Corrija os erros no formulário');
              return;
            }
      
            Loading.button(this.submitBtn, true);
      
            const payload = {
              nome: this.fields.nome?.value.trim(),
              cpf: this.fields.cpf?.value,
              password: this.fields.password?.value,
              password2: this.fields.password2?.value,
              email: this.fields.email?.value.trim(),
              telefone: this.fields.telefone?.value,
              cep: this.fields.cep?.value,
              endereco: this.fields.endereco?.value.trim(),
              numero: this.fields.numero?.value.trim(),
              complemento: this.fields.complemento?.value.trim(),
              observacoes: this.fields.observacoes?.value.trim()
            };
      
            const response = await API.post(CONFIG.endpoints.register, payload);
      
            Loading.button(this.submitBtn, false);
      
            if (response.ok) {
              Toast.success('Cadastro realizado com sucesso!');
              setTimeout(() => {
                window.location.href = '/agendamento';
              }, CONFIG.redirectDelay);
            } else {
              // Mostra erros específicos dos campos
              if (response.data.errors) {
                Object.keys(response.data.errors).forEach(field => {
                  if (this.fields[field]) {
                    FormFeedback.error(this.fields[field], response.data.errors[field]);
                  }
                });
              }
              Toast.error(response.data.error || 'Erro ao cadastrar');
            }
          }
        };
      
        // ============================================================
        // MÓDULO DE LOGIN
        // ============================================================
      
        const LoginModule = {
          form: null,
      
          init() {
            this.form = document.getElementById('loginForm');
            if (!this.form) return;
      
            console.log('Inicializando módulo de login...');
      
            this.cpfInput = document.getElementById('cpf_login');
            this.passwordInput = document.getElementById('senha_login');
            this.submitBtn = this.form.querySelector('button[type="submit"]');
            this.msgEl = document.getElementById('loginMsg');
      
            // Máscara CPF
            Masks.apply(this.cpfInput, Masks.cpf);
      
            // Toggle senha
            document.querySelectorAll('.toggle-password').forEach(btn => {
              btn.addEventListener('click', () => {
                const input = document.getElementById(btn.dataset.target);
                if (input) {
                  input.type = input.type === 'password' ? 'text' : 'password';
                  const icon = btn.querySelector('i');
                  if (icon) icon.className = input.type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
                }
              });
            });
      
            this.form.addEventListener('submit', (e) => {
              e.preventDefault();
              this.handleSubmit();
            });
          },
      
          async handleSubmit() {
            const cpf = this.cpfInput?.value;
            const password = this.passwordInput?.value;
      
            if (!cpf || !password) {
              Toast.error('Preencha CPF e senha');
              return;
            }
      
            Loading.button(this.submitBtn, true);
      
            const response = await API.post(CONFIG.endpoints.login, { cpf, password });
      
            Loading.button(this.submitBtn, false);
      
            if (response.ok) {
              Toast.success(response.data.message || 'Login realizado!');
              setTimeout(() => {
                window.location.href = '/agendamento';
              }, CONFIG.redirectDelay);
            } else {
              Toast.error(response.data.error || 'CPF ou senha incorretos');
            }
          }
        };
      
        // ============================================================
        // MÓDULO DE AGENDAMENTO
        // ============================================================
      
        const AgendamentoModule = {
          form: null,
          cliente: null,
      
          async init() {
            this.form = document.getElementById('formAgendamento');
            if (!this.form) return;
      
            console.log('Inicializando módulo de agendamento...');
      
            // Verifica autenticação
            const response = await API.get(CONFIG.endpoints.me);
            if (!response.ok || !response.data) {
              window.location.href = '/login';
              return;
            }
      
            this.cliente = response.data;
            this.preencherDadosCliente();
            
            await this.carregarServicos();
            await this.carregarBarbeiros();
            this.setupEventos();
          },
      
          preencherDadosCliente() {
            const nomeEl = document.getElementById('nome');
            const telEl = document.getElementById('telefone');
            const welcomeEl = document.getElementById('welcomeMsg');
      
            if (nomeEl) nomeEl.value = this.cliente.nome || '';
            if (telEl) telEl.value = this.cliente.telefone || '';
            if (welcomeEl) welcomeEl.textContent = `Olá, ${Utils.firstName(this.cliente.nome)}!`;
          },
      
          async carregarServicos() {
            const select = document.getElementById('servico');
            if (!select) return;
      
            const response = await API.get(CONFIG.endpoints.servicos);
            if (response.ok && response.data) {
              select.innerHTML = '<option value="">Selecione um serviço</option>';
              response.data.forEach(s => {
                select.innerHTML += `<option value="${s.id}" data-preco="${s.preco}" data-duracao="${s.duracao}">
                  ${s.nome} - R$ ${s.preco.toFixed(2)} (${s.duracao}min)
                </option>`;
              });
            }
          },
      
          async carregarBarbeiros() {
            const select = document.getElementById('barbeiro');
            if (!select) return;
      
            const response = await API.get(CONFIG.endpoints.barbeiros);
            if (response.ok && response.data) {
              select.innerHTML = '<option value="">Selecione um barbeiro</option>';
              response.data.forEach(b => {
                select.innerHTML += `<option value="${b.id}">${b.nome}</option>`;
              });
            }
          },
      
          async carregarHorarios() {
            const dataInput = document.getElementById('data_ag');
            const barbeiroSelect = document.getElementById('barbeiro');
            const servicoSelect = document.getElementById('servico');
            const horarioSelect = document.getElementById('horario');
      
            if (!dataInput?.value || !barbeiroSelect?.value || !horarioSelect) return;
      
            horarioSelect.innerHTML = '<option value="">Carregando...</option>';
            horarioSelect.disabled = true;
      
            const response = await API.get(CONFIG.endpoints.horariosDisponiveis, {
              data: dataInput.value,
              barbeiro: barbeiroSelect.value,
              servico: servicoSelect?.value || ''
            });
      
            horarioSelect.disabled = false;
      
            if (response.ok && response.data.horarios) {
              if (response.data.horarios.length === 0) {
                horarioSelect.innerHTML = '<option value="">Nenhum horário disponível</option>';
              } else {
                horarioSelect.innerHTML = '<option value="">Selecione um horário</option>';
                response.data.horarios.forEach(h => {
                  horarioSelect.innerHTML += `<option value="${h}">${h}</option>`;
                });
              }
            } else {
              horarioSelect.innerHTML = '<option value="">Erro ao carregar</option>';
            }
          },
      
          setupEventos() {
            const dataInput = document.getElementById('data_ag');
            const barbeiroSelect = document.getElementById('barbeiro');
            const servicoSelect = document.getElementById('servico');
      
            // Define data mínima como hoje
            if (dataInput) {
              const hoje = new Date().toISOString().split('T')[0];
              dataInput.min = hoje;
              dataInput.addEventListener('change', () => this.carregarHorarios());
            }
      
            if (barbeiroSelect) {
              barbeiroSelect.addEventListener('change', () => this.carregarHorarios());
            }
      
            if (servicoSelect) {
              servicoSelect.addEventListener('change', () => {
                this.atualizarResumo();
                this.carregarHorarios();
              });
            }
      
            // Submit
            this.form.addEventListener('submit', (e) => {
              e.preventDefault();
              this.handleSubmit();
            });
          },
      
          atualizarResumo() {
            const servicoSelect = document.getElementById('servico');
            const resumoEl = document.getElementById('resumoServico');
            
            if (!servicoSelect || !resumoEl) return;
      
            const option = servicoSelect.selectedOptions[0];
            if (option && option.value) {
              const preco = option.dataset.preco;
              const duracao = option.dataset.duracao;
              resumoEl.innerHTML = `<strong>Valor:</strong> R$ ${parseFloat(preco).toFixed(2)} | <strong>Duração:</strong> ${duracao} min`;
            } else {
              resumoEl.innerHTML = '';
            }
          },
      
          async handleSubmit() {
            const payload = {
              servico: document.getElementById('servico')?.value,
              barbeiro: document.getElementById('barbeiro')?.value,
              data: document.getElementById('data_ag')?.value,
              horario: document.getElementById('horario')?.value,
              observacoes: document.getElementById('obs')?.value || ''
            };
      
            if (!payload.servico || !payload.barbeiro || !payload.data || !payload.horario) {
              Toast.error('Preencha todos os campos obrigatórios');
              return;
            }
      
            const submitBtn = this.form.querySelector('button[type="submit"]');
            Loading.button(submitBtn, true);
      
            const response = await API.post(CONFIG.endpoints.agendar, payload);
      
            Loading.button(submitBtn, false);
      
            if (response.ok) {
              Toast.success('Agendamento realizado com sucesso!');
              setTimeout(() => {
                window.location.href = '/sucesso';
              }, CONFIG.redirectDelay);
            } else if (response.status === 401) {
              window.location.href = '/login';
            } else if (response.status === 409) {
              Toast.error('Horário não disponível. Escolha outro.');
              this.carregarHorarios();
            } else {
              Toast.error(response.data.error || 'Erro ao agendar');
            }
          }
        };
      
        // ============================================================
        // MÓDULO MEUS AGENDAMENTOS
        // ============================================================
      
        const MeusAgendamentosModule = {
          async init() {
            const container = document.getElementById('listaAgendamentos');
            if (!container) return;
      
            console.log('Inicializando módulo meus agendamentos...');
      
            await this.carregar(container);
          },
      
          async carregar(container) {
            container.innerHTML = '<p class="loading">Carregando...</p>';
      
            const response = await API.get(CONFIG.endpoints.meusAgendamentos, { periodo: 'todos' });
      
            if (!response.ok) {
              container.innerHTML = '<p class="error">Erro ao carregar agendamentos</p>';
              return;
            }
      
            const { agendamentos } = response.data;
      
            if (!agendamentos || agendamentos.length === 0) {
              container.innerHTML = '<p class="empty">Você ainda não tem agendamentos</p>';
              return;
            }
      
            container.innerHTML = agendamentos.map(ag => this.renderCard(ag)).join('');
      
            // Event listeners para cancelar
            container.querySelectorAll('.btn-cancelar').forEach(btn => {
              btn.addEventListener('click', () => this.cancelar(btn.dataset.id));
            });
          },
      
          renderCard(ag) {
            const statusClass = {
              pendente: 'status-pendente',
              confirmado: 'status-confirmado',
              concluido: 'status-concluido',
              cancelado: 'status-cancelado'
            };
      
            const podeCancelar = ag.status !== 'cancelado' && ag.status !== 'concluido';
      
            return `
              <div class="agendamento-card ${statusClass[ag.status] || ''}">
                <div class="ag-header">
                  <span class="ag-data">${Utils.formatDate(ag.data)} às ${ag.horario}</span>
                  <span class="ag-status">${ag.status}</span>
                </div>
                <div class="ag-body">
                  <p><strong>Serviço:</strong> ${ag.servico_nome}</p>
                  <p><strong>Barbeiro:</strong> ${ag.barbeiro_nome}</p>
                  ${ag.preco ? `<p><strong>Valor:</strong> R$ ${ag.preco.toFixed(2)}</p>` : ''}
                </div>
                ${podeCancelar ? `
                  <div class="ag-footer">
                    <button class="btn btn-danger btn-sm btn-cancelar" data-id="${ag.id}">
                      Cancelar
                    </button>
                  </div>
                ` : ''}
              </div>
            `;
          },
      
          async cancelar(id) {
            if (!confirm('Deseja realmente cancelar este agendamento?')) return;
      
            const response = await API.post(CONFIG.endpoints.cancelarAgendamento.replace('{id}', id));
      
            if (response.ok) {
              Toast.success('Agendamento cancelado');
              const container = document.getElementById('listaAgendamentos');
              if (container) this.carregar(container);
            } else {
              Toast.error(response.data.error || 'Erro ao cancelar');
            }
          }
        };
      
        // ============================================================
        // INICIALIZAÇÃO
        // ============================================================
      
        document.addEventListener('DOMContentLoaded', () => {
          console.log('BarbLab JS v2.0 carregado');
      
          // Inicializa módulos baseado na página
          CadastroModule.init();
          LoginModule.init();
          AgendamentoModule.init();
          MeusAgendamentosModule.init();

          // Logout global
          document.querySelectorAll('.btn-logout, #btnLogout').forEach(btn => {
            btn.addEventListener('click', async (e) => {
              e.preventDefault();
              const response = await API.post(CONFIG.endpoints.logout);
              if (response.ok) {
                Toast.success('Logout realizado');
                setTimeout(() => window.location.href = '/', CONFIG.redirectDelay);
              }
            });
          });
      
          // Menu mobile toggle
          const menuToggle = document.getElementById('menuToggle');
          const navMenu = document.querySelector('nav');
          if (menuToggle && navMenu) {
            menuToggle.addEventListener('click', () => {
              navMenu.classList.toggle('active');
            });
          }
      
          // Fecha menu ao clicar em link (mobile)
          document.querySelectorAll('nav a').forEach(link => {
            link.addEventListener('click', () => {
              if (navMenu) navMenu.classList.remove('active');
            });
          });
      
          // Auto-hide header on scroll (mobile)
          let lastScroll = 0;
          const header = document.querySelector('.site-header');
          if (header && Utils.isMobile()) {
            window.addEventListener('scroll', Utils.debounce(() => {
              const currentScroll = window.pageYOffset;
              if (currentScroll > lastScroll && currentScroll > 100) {
                header.style.transform = 'translateY(-100%)';
              } else {
                header.style.transform = 'translateY(0)';
              }
              lastScroll = currentScroll;
            }, 100));
          }
      
        });
      
        // ============================================================
        // EXPÕE GLOBALMENTE (opcional, para debug)
        // ============================================================
      
        window.BarbLab = {
          Utils,
          Masks,
          Validators,
          API,
          Toast,
          Loading,
          FormFeedback,
          CEPService
        };
      
      })();
      