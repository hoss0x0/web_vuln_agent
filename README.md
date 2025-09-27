# Web Vulnerability Testing Agent

An intelligent agent for automated web vulnerability testing using advanced RAG (Retrieval Augmented Generation) techniques and LLM integration.

## 🔥 Key Features

- **Advanced RAG System**: Enhanced retrieval and response generation using state-of-the-art language models
- **Intelligent Testing**: Smart vulnerability detection using context-aware testing strategies
- **Dynamic Payload Generation**: Adaptive payload mutation based on application responses
- **Security-First Design**: Built-in safety monitors and WAF detection capabilities
- **Comprehensive Logging**: Detailed activity tracking with security event monitoring
- **Memory Management**: Efficient handling of test cases and results using vector databases
- **Automated Analysis**: Smart response analysis and impact scoring

## 🏗️ Architecture

```
agent/           - Core agent implementation
chains/          - Chain components for different testing phases
├── analysis/    - Result analysis and confidence scoring
├── dispatch/    - Request handling and logging
├── evaluation/  - Response evaluation
├── execution/   - Payload execution
├── initialization/ - Setup and bootstrapping
├── interception/   - Request interception and analysis
├── learning/    - Memory management and learning
├── payloads/    - Payload management
├── planning/    - Attack planning and strategy
├── reporting/   - Report generation
├── retry/       - Retry mechanisms
├── safety/      - Safety controls
└── waf/         - WAF detection and evasion
```

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- Virtual environment (recommended)
- Required Python packages

### Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd web_vuln_agent
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Linux/Mac
# or
.venv\Scripts\activate  # On Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## 🔧 Configuration

Configuration files are located in the `config/` directory:

- `input_discovery.yaml`: Input discovery settings
- `masking_config.yaml`: Data masking rules
- `memory_config.yaml`: Memory management settings
- `mutation_config.yaml`: Payload mutation parameters
- `parser_config.yaml`: Request parsing configuration
- `payload_analyzer.yaml`: Payload analysis settings
- `session_config.yaml`: Session management
- `summary_config.yaml`: Summary generation parameters

## 💻 Usage

1. Configure your testing environment in the appropriate config files.

2. Start the agent:
```bash
python agent/main.py
```

3. Monitor the logs in `logs/` directory.

## 🛡️ Safety Features

- **WAF Detection**: Automatic detection of Web Application Firewalls
- **Safety Monitors**: Real-time monitoring of test impact
- **Stop Triggers**: Automatic halt on dangerous conditions
- **PII Masking**: Protection of sensitive data
- **Rate Limiting**: Smart request rate management

## 📝 Components

### Analysis Chain
- Confidence scoring for results
- Detection heuristics
- Response difference analysis

### Dispatch Chain
- Proxy request dispatching
- Request injection handling
- Comprehensive logging

### Evaluation Chain
- Response analysis
- Impact assessment
- Vulnerability verification

### Learning Chain
- Memory management
- PII data masking
- Summary generation

### Payload Chain
- Dynamic payload generation
- Mutation strategies
- Payload metadata management

### Planning Chain
- Attack strategy planning
- Vulnerability mapping
- Test case generation

### Safety Chain
- Security monitoring
- Stop condition management
- Impact assessment

### WAF Chain
- WAF detection
- Evasion strategies
- Adaptive techniques

## 🔍 Vector Database

The system uses ChromaDB for efficient storage and retrieval of:
- Test cases
- Payload patterns
- Response signatures
- Learning outcomes

## 📊 Logging System

Advanced logging with:
- Rotation management
- Security event tracking
- Performance monitoring
- Debug diagnostics

## ⚡ Performance

The agent includes various optimizations:
- Parallel processing
- Result caching
- Batch operations
- Resource management

## 🔐 Security Notes

- Always use in authorized testing environments
- Monitor system impact
- Review logs regularly
- Follow security policies
- Handle findings responsibly

## 🛠️ Development

### Adding New Features

1. Create feature branch
2. Implement changes
3. Add tests
4. Update documentation
5. Submit pull request

### Testing

```bash
# Run unit tests
python -m pytest tests/

# Run specific test suite
python -m pytest tests/test_payloads.py
```

## 📚 Documentation

Detailed documentation for each component is available in their respective directories:
- `agent/`: Core agent documentation
- `chains/`: Chain component details
- `config/`: Configuration guides
- `utils/`: Utility function references

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
2. Commit your changes
3. Push to the branch
4. Create a new Pull Request

## 📄 License

[Your License] - See LICENSE file for details

## ✨ Acknowledgments

- Contributors
- Testing frameworks
- Security research community

## ⚠️ Disclaimer

This tool is for authorized security testing only. Users are responsible for obtaining proper authorization before testing any systems.
