#ifndef BOOST_NETWORK_PROTOCOL_HTTP_CLIENT_CONNECTION_SSL_DELEGATE_IPP_20110819
#define BOOST_NETWORK_PROTOCOL_HTTP_CLIENT_CONNECTION_SSL_DELEGATE_IPP_20110819

// Copyright 2011 Dean Michael Berris (dberris@google.com).
// Copyright 2011 Google, Inc.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <boost/network/protocol/http/client/connection/ssl_delegate.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/bind.hpp>

boost::network::http::impl::ssl_delegate::ssl_delegate(
    asio::io_service &service, bool always_verify_peer,
    optional<std::string> certificate_filename,
    optional<std::string> verify_path,
    optional<std::string> certificate_file,
    optional<std::string> private_key_file,
    optional<std::string> ciphers,
    long ssl_options)
    : service_(service),
      certificate_filename_(certificate_filename),
      verify_path_(verify_path),
      certificate_file_(certificate_file),
      private_key_file_(private_key_file),
      ciphers_(ciphers),
      ssl_options_(ssl_options),
      always_verify_peer_(always_verify_peer) {}

void boost::network::http::impl::ssl_delegate::connect(
    asio::ip::tcp::endpoint &endpoint, std::string host,
    boost::uint16_t port, boost::uint16_t source_port,
    function<void(system::error_code const &)> handler,
    bool connect_via_proxy,
    optional<std::string> proxy_username,
    optional<std::string> proxy_password) {
  context_.reset(
      new asio::ssl::context(service_, asio::ssl::context::sslv23_client));
  if (ciphers_) {
    ::SSL_CTX_set_cipher_list(context_->native_handle(), ciphers_->c_str());
  }
  if (ssl_options_ != 0) {
    context_->set_options(ssl_options_);
  }
  if (certificate_filename_ || verify_path_) {
    context_->set_verify_mode(asio::ssl::context::verify_peer);
    if (certificate_filename_)
      context_->load_verify_file(*certificate_filename_);
    if (verify_path_) context_->add_verify_path(*verify_path_);
  } else {
    if (always_verify_peer_) {
      context_->set_verify_mode(asio::ssl::context::verify_peer);
      // use openssl default verify paths.  uses openssl environment variables
      // SSL_CERT_DIR, SSL_CERT_FILE
      context_->set_default_verify_paths();
	 } else
      context_->set_verify_mode(asio::ssl::context::verify_none);
  }
  if (certificate_file_)
    context_->use_certificate_file(*certificate_file_,
                                   boost::asio::ssl::context::pem);
  if (private_key_file_)
    context_->use_private_key_file(*private_key_file_,
                                   boost::asio::ssl::context::pem);

  tcp_socket_.reset(new asio::ip::tcp::socket(service_, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), source_port)));
  socket_.reset(
      new asio::ssl::stream<asio::ip::tcp::socket&>(*(tcp_socket_.get()), *context_));

  if (always_verify_peer_)
    socket_->set_verify_callback(boost::asio::ssl::rfc2818_verification(host));
  socket_->lowest_layer().async_connect(
      endpoint,
      service_.wrap(::boost::bind(
          &boost::network::http::impl::ssl_delegate::handle_connected,
          boost::network::http::impl::ssl_delegate::shared_from_this(),
          asio::placeholders::error, handler,
          connect_via_proxy, host, port, proxy_username, proxy_password)));
}

void boost::network::http::impl::ssl_delegate::handle_connected(
    system::error_code const &ec,
    function<void(system::error_code const &)> handler,
    bool connect_via_proxy,
    std::string const &host,
    boost::uint16_t port,
    optional<std::string> proxy_username,
    optional<std::string> proxy_password) {
  if (!ec) {
    if (connect_via_proxy) {
      // If PROXY establish connection via Proxy --> send CONNECT request
      asio::streambuf command_streambuf;
      // FIXME fill connect_streambuf with CONNECT request ...

      {
        std::ostream request_stream(&command_streambuf);

        request_stream << "CONNECT " << host << ":" << port << " HTTP/1.1\r\n";
        request_stream << "Host: " << host << ":" << port << "\r\n";

        if (proxy_username && proxy_password) {
          std::string user_pass = *proxy_username + ":" + *proxy_password;
          std::string encoded_user_pass;

          message::base64_encode(user_pass, encoded_user_pass);
          request_stream << "Proxy-Authorization: Basic " << encoded_user_pass << "\r\n";
        }

        request_stream << "\r\n";
      }

      asio::async_write(socket_->next_layer(),
                        command_streambuf,
                        service_.wrap(::boost::bind(
                            &boost::network::http::impl::ssl_delegate::handle_proxy_sent_request,
                            boost::network::http::impl::ssl_delegate::shared_from_this(),
                            handler, asio::placeholders::error, asio::placeholders::bytes_transferred)));
    }
    else {
        socket_->async_handshake(asio::ssl::stream_base::client, handler);
    }
  } else {
    handler(ec);
  }
}

void boost::network::http::impl::ssl_delegate::write(
    asio::streambuf &command_streambuf,
    function<void(system::error_code const &, size_t)> handler) {
  asio::async_write(*socket_, command_streambuf, handler);
}

void boost::network::http::impl::ssl_delegate::read_some(
    asio::mutable_buffers_1 const &read_buffer,
    function<void(system::error_code const &, size_t)> handler) {
  socket_->async_read_some(read_buffer, handler);
}

void boost::network::http::impl::ssl_delegate::disconnect() {
  if (socket_.get() && socket_->lowest_layer().is_open()) {
    boost::system::error_code ignored;
    socket_->lowest_layer().shutdown(
        boost::asio::ip::tcp::socket::shutdown_both, ignored);
    if (!ignored) {
      socket_->lowest_layer().close(ignored);
    }
  }
}

boost::network::http::impl::ssl_delegate::~ssl_delegate() {}

void boost::network::http::impl::ssl_delegate::handle_proxy_sent_request(
    function<void(system::error_code const &)> handler,
    boost::system::error_code const& ec,
    std::size_t bytes_transferred) {
  boost::asio::async_read_until(
    socket_->next_layer(), response_buffer_, "\r\n\r\n",
    service_.wrap(::boost::bind(
        &boost::network::http::impl::ssl_delegate::handle_proxy_received_data,
        boost::network::http::impl::ssl_delegate::shared_from_this(),
        handler, asio::placeholders::error, asio::placeholders::bytes_transferred)));
}

void boost::network::http::impl::ssl_delegate::handle_proxy_received_data(
    function<void(system::error_code const &)> handler,
    boost::system::error_code const& ec,
    std::size_t bytes_transferred) {
  std::istream response_stream(&response_buffer_);
  std::string http_tag;
  boost::uint16_t http_status_code = 0;

  response_stream >> http_tag;

  if (http_tag.substr(0, 4) == "HTTP") {
    response_stream >> http_status_code;
  }

  if (http_status_code == 200) {
    socket_->async_handshake(asio::ssl::stream_base::client, handler);
  }
  else {
    // FIXME set error code to something meaningful
    boost::system::error_code ignored;
    socket_->lowest_layer().close(ignored);

    handler(ec);
  }
}

#endif /* BOOST_NETWORK_PROTOCOL_HTTP_CLIENT_CONNECTION_SSL_DELEGATE_IPP_20110819 \
          */
