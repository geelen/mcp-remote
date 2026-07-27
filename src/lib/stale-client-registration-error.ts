export class StaleClientRegistrationError extends Error {
  constructor() {
    super('Cached OAuth client registration is no longer valid')
    this.name = 'StaleClientRegistrationError'
  }
}
