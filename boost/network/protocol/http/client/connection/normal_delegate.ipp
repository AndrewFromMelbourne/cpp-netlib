#ifndef BOOST_NETWORK_PROTOCOL_HTTP_CLIENT_CONNECTION_NORMAL_DELEGATE_IPP_20110819
#define BOOST_NETWORK_PROTOCOL_HTTP_CLIENT_CONNECTION_NORMAL_DELEGATE_IPP_20110819

// Copyright 2011 Dean Michael Berris (dberris@google.com).
// Copyright 2011 Google, Inc.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/write.hpp>
#include <boost/function.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/network/protocol/http/client/connection/normal_delegate.hpp>
#include <boost/network/protocol/http/message.hpp>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>

boost::network::http::impl::normal_delegate::normal_delegate(
    asio::io_service &service)
    : service_(service) {}

void boost::network::http::impl::normal_delegate::connect(
    asio::ip::tcp::endpoint &endpoint, std::string host,
    boost::uint16_t port, boost::uint16_t source_port,
    function<void(system::error_code const &)> handler,
    bool connect_via_proxy,
    optional<std::string> proxy_username,
    optional<std::string> proxy_password) {
  // TODO(dberris): review parameter necessity.
  (void)host;

  socket_.reset(new asio::ip::tcp::socket(service_, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), source_port)));
  socket_->async_connect(
      endpoint,
      service_.wrap(::boost::bind(
          &boost::network::http::impl::normal_delegate::handle_connected,
          boost::network::http::impl::normal_delegate::shared_from_this(),
          asio::placeholders::error, handler,
          connect_via_proxy, host, port, proxy_username, proxy_password)));
}

void boost::network::http::impl::normal_delegate::handle_connected(
    system::error_code const &ec,
    function<void(system::error_code const &)> handler,
    bool connect_via_proxy,
    std::string const &host,
    boost::uint16_t port,
    optional<std::string> proxy_username,
    optional<std::string> proxy_password) {
  if ((!ec) && connect_via_proxy) {
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

    write(command_streambuf,
          service_.wrap(::boost::bind(
              &boost::network::http::impl::normal_delegate::handle_proxy_sent_request,
              boost::network::http::impl::normal_delegate::shared_from_this(),
              handler, asio::placeholders::error, asio::placeholders::bytes_transferred)));
  }
  else {
    handler(ec);
  }
}

void boost::network::http::impl::normal_delegate::write(
    asio::streambuf &command_streambuf,
    function<void(system::error_code const &, size_t)> handler) {
  asio::async_write(*socket_, command_streambuf, handler);
}

void boost::network::http::impl::normal_delegate::read_some(
    asio::mutable_buffers_1 const &read_buffer,
    function<void(system::error_code const &, size_t)> handler) {
  socket_->async_read_some(read_buffer, handler);
}

void boost::network::http::impl::normal_delegate::disconnect() {
  if (socket_.get() && socket_->is_open()) {
    boost::system::error_code ignored;
    socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
    if (!ignored) {
      socket_->close(ignored);
    }
  }
}

boost::network::http::impl::normal_delegate::~normal_delegate() {}

void boost::network::http::impl::normal_delegate::handle_proxy_sent_request(
    function<void(system::error_code const &)> handler,
    boost::system::error_code const& ec,
    std::size_t bytes_transferred) {

  boost::asio::async_read_until(
    *socket_, response_buffer_, "\r\n\r\n",
    service_.wrap(::boost::bind(
        &boost::network::http::impl::normal_delegate::handle_proxy_received_data,
        boost::network::http::impl::normal_delegate::shared_from_this(),
        handler, asio::placeholders::error, asio::placeholders::bytes_transferred)));
}

void boost::network::http::impl::normal_delegate::handle_proxy_received_data(
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

  if (http_status_code != 200) {
    // FIXME set error code to something meaningful
    boost::system::error_code ignored;
    socket_->lowest_layer().close(ignored);
  }

  handler(ec);
}

#endif /* BOOST_NETWORK_PROTOCOL_HTTP_CLIENT_CONNECTION_NORMAL_DELEGATE_IPP_20110819 \
          */
